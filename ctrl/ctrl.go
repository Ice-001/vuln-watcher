package ctrl

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"entgo.io/ent/dialect"
	entSql "entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/schema"
	_ "github.com/go-sql-driver/mysql"
	"github.com/google/go-github/v53/github"
	"github.com/hashicorp/go-multierror"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/kataras/golog"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"modernc.org/sqlite"

	"github.com/vuln-watcher/ent"
	"github.com/vuln-watcher/ent/migrate"
	"github.com/vuln-watcher/ent/vulninformation"
	"github.com/vuln-watcher/grab"
	"github.com/vuln-watcher/push"
	"github.com/vuln-watcher/util"
)

func init() {
	sql.Register("sqlite3", &sqlite.Driver{})
	sql.Register("postgres", &stdlib.Driver{})
}

const (
	InitPageLimit   = 3
	UpdatePageLimit = 1
)

type ScanStats struct {
	TotalCollected int
	NotValuable    int
	Pushed         int
}

type WatchVulnApp struct {
	config     *WatchVulnAppConfig
	textPusher push.TextPusher
	rawPusher  push.RawPusher

	log          *golog.Logger
	db           *ent.Client
	sqlDB        *sql.DB
	githubClient *github.Client
	grabbers     []grab.Grabber
	prs          []*github.PullRequest
	mdDir        string
	noPush       bool
}

func NewApp(config *WatchVulnAppConfig) (*WatchVulnApp, error) {
	config.Init()
	drvName, connStr, err := config.DBConnForEnt()
	if err != nil {
		return nil, err
	}
	textPusher, rawPusher, err := config.GetPusher()
	if err != nil {
		return nil, err
	}
	// SQLite 使用绝对路径
	if drvName == dialect.SQLite {
		var absStr string
		absStr, err = ensureAbsPath(connStr)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get absolute path for sqlite db")
		}
		golog.Infof("SQLite connection: original=%s, absolute=%s", connStr, absStr)
		connStr = absStr
	}
	drv, err := entSql.Open(drvName, connStr)
	if err != nil {
		return nil, errors.Wrap(err, "failed opening connection to db")
	}
	db := drv.DB()
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(time.Minute * 1)
	db.SetMaxIdleConns(1)
	dbClient := ent.NewClient(ent.Driver(drv))
	sqlDB := drv.DB()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	needsInit := true
	if *config.DiffMode {
		count, err := dbClient.VulnInformation.Query().Count(ctx)
		if err == nil && count >= 0 {
			needsInit = false
			golog.Infof("database already exists, skipping schema init")
		}
	}

	if needsInit {
		migrateOptions := []schema.MigrateOption{
			migrate.WithDropIndex(false),
			migrate.WithDropColumn(false),
		}
		if err := dbClient.Schema.Create(ctx, migrateOptions...); err != nil {
			return nil, errors.Wrap(err, "failed creating schema resources")
		}
	}

	var grabs []grab.Grabber
	for _, part := range config.Sources {
		part = strings.ToLower(strings.TrimSpace(part))
		switch part {
		case "chaitin":
			grabs = append(grabs, grab.NewChaitinCrawler())
		case "avd":
			grabs = append(grabs, grab.NewAVDCrawler())
		case "nox", "ti":
			grabs = append(grabs, grab.NewTiCrawler())
		case "oscs":
			grabs = append(grabs, grab.NewOSCSCrawler())
		case "seebug":
			grabs = append(grabs, grab.NewSeebugCrawler())
		case "threatbook":
			grabs = append(grabs, grab.NewThreatBookCrawler())
		case "struts2", "structs2":
			grabs = append(grabs, grab.NewStruts2Crawler())
		case "kev":
			grabs = append(grabs, grab.NewKEVCrawler())
		case "venustech":
			grabs = append(grabs, grab.NewVenustechCrawler())
		default:
			return nil, fmt.Errorf("invalid grab source %s", part)
		}
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = http.ProxyFromEnvironment
	githubClient := github.NewClient(&http.Client{
		Timeout:   time.Second * 10,
		Transport: tr,
	})

	return &WatchVulnApp{
		config:       config,
		textPusher:   textPusher,
		rawPusher:    rawPusher,
		log:          golog.Child("[ctrl]"),
		db:           dbClient,
		sqlDB:        sqlDB,
		githubClient: githubClient,
		grabbers:     grabs,
		mdDir:        config.MdDir,
		noPush:       config.NoPush,
	}, nil
}

func (w *WatchVulnApp) Run(ctx context.Context) error {
	if *w.config.DiffMode {
		w.log.Info("running in diff mode, skip init vuln database")

		if w.textPusher != nil {
			providerStatus := "## WatchVuln 数据源状态\n\n"
			location, _ := time.LoadLocation("Asia/Shanghai")
			for _, grab := range w.grabbers {
				providerStatus += fmt.Sprintf("- **%s**: ✅ 正常\n", grab.ProviderInfo().DisplayName)
			}
			providerStatus += fmt.Sprintf("\n- **扫描时间**: %s", time.Now().In(location).Format("2006-01-02 15:04:05"))
			w.textPusher.PushMarkdown("WatchVuln 开始扫描", providerStatus)
		}

		w.collectAndPush(ctx)
		w.log.Info("diff finished")
		return nil
	}

	if w.config.Test {
		w.log.Info("running in test mode, the mocked message will be sent")
		if err := w.testPushMessage(); err != nil {
			return err
		}
		w.log.Infof("test finished")
		return nil
	}

	w.log.Infof("initialize local database..")
	success, fail := w.initData(ctx)
	w.grabbers = success
	localCount, err := w.db.VulnInformation.Query().Count(ctx)
	if err != nil {
		return err
	}
	w.log.Infof("system init finished, local database has %d vulns", localCount)
	if !*w.config.NoStartMessage {
		providers := make([]*grab.Provider, 0, 10)
		failed := make([]*grab.Provider, 0, 10)
		for _, p := range w.grabbers {
			providers = append(providers, p.ProviderInfo())
		}
		for _, p := range fail {
			failed = append(failed, p.ProviderInfo())
		}
		msg := &push.InitialMessage{
			Version:        w.config.Version,
			VulnCount:      localCount,
			Interval:       w.config.IntervalParsed.String(),
			Provider:       providers,
			FailedProvider: failed,
		}
		if pushErr := w.textPusher.PushMarkdown("WatchVuln 初始化完成", push.RenderInitialMsg(msg)); pushErr != nil {
			return pushErr
		}
		if pushErr := w.rawPusher.PushRaw(push.NewRawInitialMessage(msg)); pushErr != nil {
			return pushErr
		}
	}

	if w.config.OnceMode {
		w.log.Info("once mode: run once and exit")
		return nil
	}

	w.log.Infof("ticking every %s", w.config.Interval)

	defer func() {
		msg := "注意: WatchVuln 进程退出"
		if err = w.textPusher.PushText(msg); err != nil {
			w.log.Error(err)
		}
		if err = w.rawPusher.PushRaw(push.NewRawTextMessage(msg)); err != nil {
			w.log.Error(err)
		}
		time.Sleep(time.Second)
	}()

	ticker := time.NewTicker(w.config.IntervalParsed)
	defer ticker.Stop()
	location, _ := time.LoadLocation("Asia/Shanghai")
	for {
		w.prs = nil
		w.log.Infof("next checking at %s\n", time.Now().In(location).Add(w.config.IntervalParsed).Format("2006-01-02 15:04:05"))

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			hour := time.Now().In(location).Hour()
			if hour >= 0 && hour < 7 && !*w.config.NoSleep {
				// we must sleep in this time
				w.log.Infof("sleeping..")
				continue
			}
			w.collectAndPush(ctx)
		}
	}
}

func (w *WatchVulnApp) collectAndPush(ctx context.Context) {
	vulns, err := w.collectUpdate(ctx)
	if err != nil {
		w.log.Errorf("failed to get updates, %s", err)
	}
	w.log.Infof("found %d new vulns in this ticking", len(vulns))

	if w.mdDir != "" {
		vulnMaps := make([]map[string]interface{}, 0, len(vulns))
		for _, v := range vulns {
			vulnMaps = append(vulnMaps, map[string]interface{}{
				"unique_key":    v.UniqueKey,
				"title":         v.Title,
				"description":   v.Description,
				"severity":      string(v.Severity),
				"cve":           v.CVE,
				"disclosure":    v.Disclosure,
				"solutions":     v.Solutions,
				"github_search": v.GithubSearch,
				"references":    v.References,
				"tags":          v.Tags,
				"from":          v.From,
				"reason":        v.Reason,
			})
		}
		if err := util.WriteVulnMapToMarkdownFile(w.mdDir, vulnMaps); err != nil {
			w.log.Errorf("failed to write md file, %s", err)
		} else {
			w.log.Infof("written %d vulns to md file", len(vulns))
		}
	}

	if w.noPush {
		w.log.Info("no push mode, skip all message push")
		allVulns, err := w.db.VulnInformation.Query().Where(vulninformation.Pushed(false)).All(ctx)
		if err != nil {
			w.log.Errorf("failed to query unpushed vulns: %v", err)
		} else {
			w.log.Infof("marking %d vulns as pushed", len(allVulns))
			for _, v := range allVulns {
				_, err = w.db.VulnInformation.Update().Where(vulninformation.ID(v.ID)).SetPushed(true).Save(ctx)
				if err != nil {
					w.log.Errorf("failed to update pushed status for %s: %v", v.Key, err)
				}
			}
		}
		w.sendScanReport(ctx, &ScanStats{TotalCollected: len(vulns), NotValuable: 0, Pushed: 0})
		return
	}

	stats := &ScanStats{TotalCollected: len(vulns)}

	if len(vulns) == 0 {
		w.sendScanReport(ctx, stats)
		return
	}

	for _, v := range vulns {
		if w.config.NoFilter || v.Creator.IsValuable(v) {
			dbVuln, err := w.db.VulnInformation.Query().Where(vulninformation.Key(v.UniqueKey)).First(ctx)
			if err != nil {
				w.log.Errorf("failed to query %s from db %s", v.UniqueKey, err)
				continue
			}
			if dbVuln.Pushed {
				w.log.Infof("%s has been pushed, skipped", v)
				continue
			}
			if v.CVE != "" && *w.config.EnableCVEFilter {
				others, err := w.db.VulnInformation.Query().
					Where(vulninformation.And(vulninformation.Cve(v.CVE), vulninformation.Pushed(true))).All(ctx)
				if err != nil {
					w.log.Errorf("failed to query %s from db %s", v.UniqueKey, err)
					continue
				}
				if len(others) != 0 {
					ids := make([]string, 0, len(others))
					for _, o := range others {
						ids = append(ids, o.Key)
					}
					w.log.Infof("found new cve but other source has already pushed, others: %v", ids)
					continue
				}
			}

			if len(w.config.BlackKeywords) != 0 {
				shouldContinue := false
				for _, p := range w.config.BlackKeywords {
					if strings.Contains(strings.ToLower(v.Title), strings.ToLower(p)) {
						w.log.Infof("skipped %s as in product filter list", v)
						shouldContinue = true
					}
				}
				if shouldContinue {
					continue
				}
			}

			if len(w.config.WhiteKeywords) != 0 {
				found := false
				for _, p := range w.config.WhiteKeywords {
					if strings.Contains(strings.ToLower(v.Title), strings.ToLower(p)) {
						found = true
						break
					}
					if strings.Contains(strings.ToLower(v.Description), strings.ToLower(p)) {
						found = true
						break
					}
				}
				if !found {
					w.log.Infof("skipped %s as not in product filter list", v)
					continue
				}
			}

			if v.Disclosure != "" {
				disclosureTime, err := time.Parse("2006-01-02", v.Disclosure)
				if err == nil {
					if time.Since(disclosureTime) > time.Hour*24*365 {
						w.log.Infof("skipped %s as disclosure date %s older than 1 year", v, v.Disclosure)
						continue
					}
				}
			}

			if v.CVE != "" && !*w.config.NoGithubSearch {
				links, err := w.FindGithubPoc(ctx, v.CVE)
				if err != nil {
					w.log.Warn(err)
				}
				w.log.Infof("%s found %d links from github, %v", v.CVE, len(links), links)
				if len(links) != 0 {
					v.GithubSearch = grab.MergeUniqueString(v.GithubSearch, links)
					_, err = dbVuln.Update().SetGithubSearch(v.GithubSearch).Save(ctx)
					if err != nil {
						w.log.Warnf("failed to save %s references,  %s", v.UniqueKey, err)
					}
				}
			}
			w.log.Infof("Pushing %s", v)

			i := 0
			for {
				if err := w.pushVuln(v); err == nil {
					_, err = dbVuln.Update().SetPushed(true).Save(ctx)
					if err != nil {
						w.log.Errorf("failed to save pushed %s status, %s", v.UniqueKey, err)
					}
					w.log.Infof("pushed %s successfully", v)
					stats.Pushed++
					break
				} else {
					w.log.Errorf("failed to push %s, %s", v.UniqueKey, err)
				}
				i++
				if i > w.config.PushRetryCount {
					break
				}
				w.log.Infof("retry to push %s after 30s", v.UniqueKey)
				time.Sleep(time.Second * 30)
			}
		} else {
			w.log.Infof("skipped %s as not valuable", v)
			stats.NotValuable++
		}
	}

	w.sendScanReport(ctx, stats)
}

func (w *WatchVulnApp) sendScanReport(ctx context.Context, stats *ScanStats) {
	totalCount, _ := w.db.VulnInformation.Query().Count(ctx)
	pushedCount, _ := w.db.VulnInformation.Query().Where(vulninformation.Pushed(true)).Count(ctx)
	unpushedCount, _ := w.db.VulnInformation.Query().Where(vulninformation.Pushed(false)).Count(ctx)

	duplicateCount := 0
	if *w.config.EnableCVEFilter {
		duplicateCount, _ = w.countDuplicateWithPushedCVE(ctx)
	}

	statsMsg := fmt.Sprintf("## WatchVuln 扫描报告\n\n- **数据库总数**: %d 条\n- **已推送**: %d 条\n- **未推送**: %d 条\n- **本次扫描收集**: %d 条\n- **本次推送成功**: %d 条\n- **本次跳过(价值不足)**: %d 条\n- **重复未推送(CVE去重)**: %d 条\n- **扫描时间**: %s\n- **模式**: Diff (增量)", totalCount, pushedCount, unpushedCount, stats.TotalCollected, stats.Pushed, stats.NotValuable, duplicateCount, util.GetBeijingTime().Format("2006-01-02 15:04:05"))
	w.log.Info(statsMsg)
	if w.textPusher != nil {
		w.textPusher.PushMarkdown("WatchVuln 扫描完成", statsMsg)
	}
}

func (w *WatchVulnApp) countDuplicateWithPushedCVE(ctx context.Context) (int, error) {
	pushedVulns, err := w.db.VulnInformation.Query().Where(vulninformation.Pushed(true)).All(ctx)
	if err != nil {
		return 0, err
	}

	cveSet := make(map[string]bool)
	for _, v := range pushedVulns {
		if v.Cve != "" {
			cveSet[v.Cve] = true
		}
	}

	if len(cveSet) == 0 {
		return 0, nil
	}

	duplicateCount := 0
	for cve := range cveSet {
		count, err := w.db.VulnInformation.Query().
			Where(vulninformation.And(vulninformation.Cve(cve), vulninformation.Pushed(false))).Count(ctx)
		if err != nil {
			continue
		}
		duplicateCount += count
	}
	return duplicateCount, nil
}

func (w *WatchVulnApp) pushVuln(vul *grab.VulnInfo) error {
	var pushErr *multierror.Error

	if err := w.textPusher.PushMarkdown(vul.Title, push.RenderVulnInfo(vul)); err != nil {
		pushErr = multierror.Append(pushErr, err)
	}

	if err := w.rawPusher.PushRaw(push.NewRawVulnInfoMessage(vul)); err != nil {
		pushErr = multierror.Append(pushErr, err)
	}

	return pushErr.ErrorOrNil()
}

func (w *WatchVulnApp) Close() {
	_ = w.db.Close()
}

func (w *WatchVulnApp) initData(ctx context.Context) ([]grab.Grabber, []grab.Grabber) {
	var eg errgroup.Group
	eg.SetLimit(len(w.grabbers))
	var success []grab.Grabber
	var fail []grab.Grabber
	for _, grabber := range w.grabbers {
		gb := grabber
		eg.Go(func() error {
			source := gb.ProviderInfo()
			w.log.Infof("start to init data from %s", source.Name)
			initVulns, err := gb.GetUpdate(ctx, InitPageLimit)
			if err != nil {
				fail = append(fail, gb)
				return errors.Wrap(err, source.Name)
			}

			for _, data := range initVulns {
				if _, err = w.createOrUpdate(ctx, source, data); err != nil {
					fail = append(fail, gb)
					return errors.Wrap(errors.Wrap(err, data.String()), source.Name)
				}
			}
			success = append(success, gb)
			return nil
		})
	}
	err := eg.Wait()
	if err != nil {
		w.log.Error(errors.Wrap(err, "init data"))
	}
	return success, fail
}

func (w *WatchVulnApp) collectUpdate(ctx context.Context) ([]*grab.VulnInfo, error) {
	var eg errgroup.Group
	eg.SetLimit(len(w.grabbers))

	var mu sync.Mutex
	var newVulns []*grab.VulnInfo

	for _, grabber := range w.grabbers {
		gb := grabber
		eg.Go(func() error {
			source := gb.ProviderInfo()
			dataChan, err := gb.GetUpdate(ctx, UpdatePageLimit)
			if err != nil {
				return errors.Wrap(err, gb.ProviderInfo().Name)
			}
			hasNewVuln := false
			w.log.Infof("collected %d vulns from %s", len(dataChan), source.Name)

			for _, data := range dataChan {
				isNew, err := w.createOrUpdate(ctx, source, data)
				if err != nil {
					return errors.Wrap(err, gb.ProviderInfo().Name)
				}

				// 新建的漏洞直接推送（新建时 pushed=false）
				if isNew {
					w.log.Infof("found new vuln to push: %s", data.UniqueKey)
					mu.Lock()
					newVulns = append(newVulns, data)
					mu.Unlock()
					hasNewVuln = true
					continue
				}

				// 已存在的漏洞，检查 pushed 状态
				var pushed int
				err = w.sqlDB.QueryRowContext(ctx, "SELECT pushed FROM vuln_informations WHERE `key` = ?", data.UniqueKey).Scan(&pushed)
				if err != nil {
					w.log.Errorf("failed to query pushed status for %s: %v", data.UniqueKey, err)
					continue
				}

				w.log.Infof("check vuln %s: pushed=%v (via raw SQL)", data.UniqueKey, pushed)

				// 只推送从未推送过的漏洞
				if pushed == 1 {
					w.log.Infof("%s already pushed, skipped", data.UniqueKey)
					continue
				}
				w.log.Infof("found new vuln to push: %s", data.UniqueKey)
				mu.Lock()
				newVulns = append(newVulns, data)
				mu.Unlock()
				hasNewVuln = true
			}

			// 如果一整页漏洞都是旧的，说明没有更新，不必再继续下一页了
			if !hasNewVuln {
				return nil
			}
			return nil
		})
	}
	err := eg.Wait()
	return newVulns, err
}

func (w *WatchVulnApp) createOrUpdate(ctx context.Context, source *grab.Provider, data *grab.VulnInfo) (bool, error) {
	w.log.Debugf("createOrUpdate: querying key=%s", data.UniqueKey)
	vuln, err := w.db.VulnInformation.Query().
		Where(vulninformation.Key(data.UniqueKey)).
		First(ctx)
	if err != nil {
		w.log.Infof("createOrUpdate: key=%s not found in db, will create new", data.UniqueKey)
		data.Reason = append(data.Reason, grab.ReasonNewCreated)
		newVuln, createErr := w.db.VulnInformation.
			Create().
			SetKey(data.UniqueKey).
			SetTitle(data.Title).
			SetDescription(data.Description).
			SetSeverity(string(data.Severity)).
			SetCve(data.CVE).
			SetDisclosure(data.Disclosure).
			SetSolutions(data.Solutions).
			SetReferences(data.References).
			SetPushed(false).
			SetTags(data.Tags).
			SetFrom(data.From).
			Save(ctx)
		if createErr != nil {
			return false, createErr
		}
		w.log.Infof("vuln %s(%s) created from %s", newVuln.Title, newVuln.Key, source.Name)
		return true, nil
	}

	// 任何更新（severity/tag/内容）都触发推送
	hasUpdate := false
	if string(data.Severity) != vuln.Severity {
		w.log.Infof("%s from %s change severity from %s to %s", data.Title, data.From, vuln.Severity, data.Severity)
		data.Reason = append(data.Reason, fmt.Sprintf("%s: %s => %s", grab.ReasonSeverityUpdated, vuln.Severity, data.Severity))
		hasUpdate = true
	}
	for _, newTag := range data.Tags {
		found := false
		for _, dbTag := range vuln.Tags {
			if newTag == dbTag {
				found = true
				break
			}
		}
		// tag 有更新
		if !found {
			w.log.Infof("%s from %s add new tag %s", data.Title, data.From, newTag)
			data.Reason = append(data.Reason, fmt.Sprintf("%s: %v => %v", grab.ReasonTagUpdated, vuln.Tags, data.Tags))
			hasUpdate = true
			break
		}
	}

	// 如果内容有更新，也触发推送
	if data.Title != vuln.Title || data.Description != vuln.Description {
		w.log.Infof("%s content updated, will re-push", data.UniqueKey)
		hasUpdate = true
	}

	// update - 不改变 pushed 状态
	newVuln, err := vuln.Update().SetKey(data.UniqueKey).
		SetTitle(data.Title).
		SetDescription(data.Description).
		SetSeverity(string(data.Severity)).
		SetCve(data.CVE).
		SetDisclosure(data.Disclosure).
		SetSolutions(data.Solutions).
		SetReferences(data.References).
		SetTags(data.Tags).
		SetFrom(data.From).
		Save(ctx)
	if err != nil {
		return false, err
	}
	w.log.Debugf("vuln %d updated from %s %s", newVuln.ID, newVuln.Key, source.Name)
	return hasUpdate, nil
}

func ensureAbsPath(connStr string) (string, error) {
	if strings.HasPrefix(connStr, "file:") {
		path := strings.TrimPrefix(connStr, "file:")
		if idx := strings.Index(path, "?"); idx != -1 {
			path = path[:idx]
		}
		if !filepath.IsAbs(path) {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return connStr, err
			}
			return "file:" + absPath, nil
		}
	}
	return connStr, nil
}

func (w *WatchVulnApp) FindGithubPoc(ctx context.Context, cveId string) ([]string, error) {
	var eg errgroup.Group
	var results []string
	var mu sync.Mutex

	eg.Go(func() error {
		links, err := w.findGithubRepo(ctx, cveId)
		if err != nil {
			return errors.Wrap(err, "find github repo")
		}
		mu.Lock()
		defer mu.Unlock()
		results = append(results, links...)
		return nil
	})
	eg.Go(func() error {
		links, err := w.findNucleiPR(ctx, cveId)
		if err != nil {
			return errors.Wrap(err, "find nuclei PR")
		}
		mu.Lock()
		defer mu.Unlock()
		results = append(results, links...)
		return nil
	})
	err := eg.Wait()
	return results, err
}

func (w *WatchVulnApp) findGithubRepo(ctx context.Context, cveId string) ([]string, error) {
	w.log.Infof("finding github repo of %s", cveId)
	re, err := regexp.Compile(fmt.Sprintf("(?i)[\b/_]%s[\b/_]", cveId))
	if err != nil {
		return nil, err
	}
	lastYear := time.Now().AddDate(-1, 0, 0).Format("2006-01-02")
	query := fmt.Sprintf(`language:Python language:JavaScript language:C language:C++ language:Java language:PHP language:Ruby language:Rust language:C# created:>%s %s`, lastYear, cveId)
	result, _, err := w.githubClient.Search.Repositories(ctx, query, &github.SearchOptions{
		ListOptions: github.ListOptions{Page: 1, PerPage: 100},
	})
	if err != nil {
		return nil, err
	}
	var links []string
	for _, repo := range result.Repositories {
		if re.MatchString(repo.GetHTMLURL()) {
			links = append(links, repo.GetHTMLURL())
		}
	}
	return links, nil
}

func (w *WatchVulnApp) findNucleiPR(ctx context.Context, cveId string) ([]string, error) {
	w.log.Infof("finding nuclei PR of %s", cveId)
	if w.prs == nil {
		// 检查200个pr
		for page := 1; page < 2; page++ {
			prs, _, err := w.githubClient.PullRequests.List(ctx, "projectdiscovery", "nuclei-templates", &github.PullRequestListOptions{
				State:       "all",
				ListOptions: github.ListOptions{Page: page, PerPage: 100},
			})
			if err != nil {
				if len(w.prs) == 0 {
					return nil, err
				} else {
					w.log.Warnf("list nuclei pr failed: %v", err)
					continue
				}
			}
			w.prs = append(w.prs, prs...)
		}
	}

	var links []string
	re, err := regexp.Compile(fmt.Sprintf("(?i)[\b/_]%s[\b/_]", cveId))
	if err != nil {
		return nil, err
	}
	for _, pr := range w.prs {
		if re.MatchString(pr.GetTitle()) || re.MatchString(pr.GetBody()) {
			links = append(links, pr.GetHTMLURL())
		}
	}
	return links, nil
}

func (w *WatchVulnApp) testPushMessage() error {
	// push start message
	providers := make([]*grab.Provider, 0, 10)
	failed := make([]*grab.Provider, 0, 10)
	for _, p := range w.grabbers {
		providers = append(providers, p.ProviderInfo())
	}
	msg := &push.InitialMessage{
		Version:        w.config.Version,
		VulnCount:      1024,
		Interval:       w.config.IntervalParsed.String(),
		Provider:       providers,
		FailedProvider: failed,
	}
	if err := w.textPusher.PushMarkdown("WatchVuln 初始化完成", push.RenderInitialMsg(msg)); err != nil {
		return err
	}
	if err := w.rawPusher.PushRaw(push.NewRawInitialMessage(msg)); err != nil {
		return err
	}
	w.log.Infof("start message pushed")

	// push a mocked vuln
	v := &grab.VulnInfo{
		Title:        "Watchvuln 代码执行漏洞",
		CVE:          "CVE-2033-9096",
		Severity:     "严重",
		Tags:         []string{"POC公开", "源码公开", "技术细节公开"},
		Disclosure:   "2033-06-30",
		From:         "https://github.com/vuln-watcher",
		Reason:       []string{"created"},
		Description:  "Watchvuln 存在代码执行漏洞，只要你想二开，那么就一定需要执行它原本的代码",
		GithubSearch: []string{"https://github.com/search?q=vuln-watcher&ref=opensearch&type=repositories"},
		References:   []string{"https://github.com/vuln-watcher/issues/127"},
		Solutions:    "1. 升级到最新版本\n2. 赞助作者",
	}
	if err := w.pushVuln(v); err != nil {
		return err
	}
	w.log.Infof("mocked vuln message pushed")

	// push stop message
	info := "WatchVuln 测试结束，进程即将退出"
	if err := w.textPusher.PushText(info); err != nil {
		return err
	}
	if err := w.rawPusher.PushRaw(push.NewRawTextMessage(info)); err != nil {
		return err
	}
	w.log.Infof("stop message pushed")
	return nil
}

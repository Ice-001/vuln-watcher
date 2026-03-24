package util

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func GetBeijingTime() time.Time {
	location, _ := time.LoadLocation("Asia/Shanghai")
	return time.Now().In(location)
}

func GetTodayDate() string {
	return GetBeijingTime().Format("2006-01-02")
}

func GetTodayDatePath(baseDir string) string {
	date := GetTodayDate()
	return filepath.Join(baseDir, date+".md")
}

func WriteVulnMapToMarkdownFile(baseDir string, vulns []map[string]interface{}) error {
	if len(vulns) == 0 {
		return nil
	}

	datePath := GetTodayDatePath(baseDir)

	exists, err := fileExists(datePath)
	if err != nil {
		return err
	}

	var content strings.Builder

	if !exists {
		date := GetTodayDate()
		content.WriteString(fmt.Sprintf("# 漏洞日报 - %s\n\n", date))
		content.WriteString("## 今日漏洞\n\n")
	} else {
		existingContent, err := os.ReadFile(datePath)
		if err != nil {
			return err
		}
		content.Write(existingContent)
	}

	for _, v := range vulns {
		content.WriteString(vulnMapToMarkdown(v))
	}

	err = os.WriteFile(datePath, []byte(content.String()), 0644)
	if err != nil {
		return err
	}

	return nil
}

func vulnMapToMarkdown(v map[string]interface{}) string {
	var sb strings.Builder

	title, _ := v["title"].(string)
	sb.WriteString(fmt.Sprintf("## %s\n\n", title))

	cve, _ := v["cve"].(string)
	if cve != "" {
		sb.WriteString(fmt.Sprintf("- **CVE编号:** %s\n", cve))
	} else {
		sb.WriteString("- **CVE编号:** 暂无\n")
	}

	severity, _ := v["severity"].(string)
	sb.WriteString(fmt.Sprintf("- **危害定级:** %s\n", severity))

	if tags, ok := v["tags"].([]string); ok && len(tags) > 0 {
		sb.WriteString(fmt.Sprintf("- **漏洞标签:** %s\n", strings.Join(tags, ", ")))
	}

	disclosure, _ := v["disclosure"].(string)
	sb.WriteString(fmt.Sprintf("- **披露日期:** %s\n", disclosure))

	if reason, ok := v["reason"].([]string); ok && len(reason) > 0 {
		sb.WriteString(fmt.Sprintf("- **推送原因:** %s\n", strings.Join(reason, ", ")))
	}

	from, _ := v["from"].(string)
	sb.WriteString(fmt.Sprintf("- **信息来源:** [%s](%s)\n\n", from, from))

	if desc, ok := v["description"].(string); ok && desc != "" {
		sb.WriteString("### 漏洞描述\n\n")
		sb.WriteString(desc)
		sb.WriteString("\n\n")
	}

	if solutions, ok := v["solutions"].(string); ok && solutions != "" {
		sb.WriteString("### 修复方案\n\n")
		sb.WriteString(solutions)
		sb.WriteString("\n\n")
	}

	if refs, ok := v["references"].([]string); ok && len(refs) > 0 {
		sb.WriteString("### 参考链接\n\n")
		for i, ref := range refs {
			sb.WriteString(fmt.Sprintf("%d. [%s](%s)\n", i+1, ref, ref))
		}
		sb.WriteString("\n")
	}

	if cve != "" {
		if githubSearch, ok := v["github_search"].([]string); ok && len(githubSearch) > 0 {
			sb.WriteString("### 开源检索\n\n")
			for i, link := range githubSearch {
				sb.WriteString(fmt.Sprintf("%d. [%s](%s)\n", i+1, link, link))
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("---\n\n")

	return sb.String()
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Package commentguard provides comment moderation and spam protection.
package commentguard

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	eng "github.com/nuxtblog/nuxtblog/internal/pluginsys"
	pluginsdk "github.com/nuxtblog/nuxtblog/sdk"
)

//go:embed plugin.yaml
var manifestYAML []byte

func init() {
	pluginsdk.Register(&CommentGuard{})
}

type CommentGuard struct {
	pluginsdk.BasePlugin
	ctx pluginsdk.PluginContext
}

func (p *CommentGuard) Manifest() pluginsdk.Manifest {
	return pluginsdk.ParseManifestCached("nuxtblog-plugin-comment-guard", manifestYAML)
}

func (p *CommentGuard) Activate(ctx pluginsdk.PluginContext) error {
	p.ctx = ctx
	ctx.Log.Info("Comment Guard activated (Go native)")
	return nil
}

func (p *CommentGuard) Deactivate() error { return nil }

func (p *CommentGuard) Filters() []pluginsdk.FilterDef {
	return []pluginsdk.FilterDef{
		// Filter: comment.create
		{
			Event: "filter:comment.create",
			Handler: func(fc *pluginsdk.FilterContext) {
				content, _ := fc.Data["content"].(string)
				authorEmail, _ := fc.Data["author_email"].(string)

				// 1) Min length
				minLen := p.getInt("min_content_length", 5)
				if utf8.RuneCountInString(strings.TrimSpace(content)) < minLen {
					p.recordBlock("too_short")
					fc.Abort(fmt.Sprintf("评论内容太短，至少需要 %d 个字符", minLen))
					return
				}

				// 2) Blocked words
				if blocked, word := p.checkBlockedWords(content); blocked {
					p.recordBlock("blocked_word")
					fc.Abort(fmt.Sprintf("评论包含屏蔽词: %s", word))
					return
				}

				// 3) Rate limit
				rateLimit := p.getInt("rate_limit", 5)
				if !p.checkRateLimit(authorEmail, rateLimit) {
					p.recordBlock("rate_limit")
					fc.Abort("评论过于频繁，请稍后再试")
					return
				}

				// 4) Too many links
				linkCount := len(regexp.MustCompile(`https?://`).FindAllString(content, -1))
				if linkCount > 3 {
					p.recordBlock("too_many_links")
					fc.Abort("评论包含过多链接")
					return
				}

				// 5) Mark for AI review if needed
				if p.getBool("ai_review") {
					hasChinese := regexp.MustCompile(`[\x{4e00}-\x{9fff}]`).MatchString(content)
					if !hasChinese && linkCount > 0 {
						fc.Meta["needs_ai_review"] = true
					}
				}

				p.recordPass()
			},
		},
		// Filter: comment.update
		{
			Event: "filter:comment.update",
			Handler: func(fc *pluginsdk.FilterContext) {
				content, _ := fc.Data["content"].(string)
				if blocked, word := p.checkBlockedWords(content); blocked {
					p.recordBlock("blocked_word_edit")
					fc.Abort(fmt.Sprintf("评论包含屏蔽词: %s", word))
				}
			},
		},
		// Filter: user.login — block spam email domains
		{
			Event: "filter:user.login",
			Handler: func(fc *pluginsdk.FilterContext) {
				email, _ := fc.Data["email"].(string)
				domain := ""
				if parts := strings.SplitN(email, "@", 2); len(parts) == 2 {
					domain = strings.ToLower(parts[1])
				}
				spamDomains := []string{"tempmail.com", "guerrillamail.com", "mailinator.com"}
				for _, d := range spamDomains {
					if domain == d {
						fc.Abort("此邮箱域名已被封禁")
						return
					}
				}
			},
		},
	}
}

func (p *CommentGuard) OnEvent(ctx context.Context, event string, data map[string]any) {
	switch event {
	case "comment.approved":
		if _, ok := data["moderator_id"]; ok {
			_, _ = p.ctx.Store.Increment("stats:approved")
		}
	}
}

func (p *CommentGuard) Routes(r pluginsdk.RouteRegistrar) {
	r.Handle("GET", "/api/plugin/comment-guard/stats", p.handleGetStats, pluginsdk.WithAuth("admin"))
}

// ─── AI check (called asynchronously by pipeline system) ────────────────────

func (p *CommentGuard) AICheck(content, authorName string) (isSpam bool, verdict string) {
	result, err := eng.CallAIService(context.Background(), "polish", map[string]any{
		"content": fmt.Sprintf("判断以下评论是否是垃圾评论。回复 \"spam\" 或 \"not_spam\"：\n\n%s", content),
	})
	if err != nil {
		return false, ""
	}
	lower := strings.ToLower(result)
	isSpam = strings.Contains(lower, "spam") && !strings.Contains(lower, "not_spam")
	if isSpam {
		p.ctx.Log.Warn(fmt.Sprintf("AI flagged comment as spam: \"%s...\"", truncateStr(content, 50)))
		p.recordBlock("ai_spam")
	}
	return isSpam, result
}

// ─── Route Handler ──────────────────────────────────────────────────────────

func (p *CommentGuard) handleGetStats(w http.ResponseWriter, r *http.Request) {
	month := r.URL.Query().Get("month")
	if month == "" {
		now := time.Now()
		month = fmt.Sprintf("%d-%02d", now.Year(), now.Month())
	}

	// Read known stat keys
	statKeys := []string{"blocked", "passed", "blocked:too_short", "blocked:blocked_word",
		"blocked:rate_limit", "blocked:too_many_links", "blocked:ai_spam", "blocked:blocked_word_edit"}
	stats := make(map[string]any)
	for _, k := range statKeys {
		key := fmt.Sprintf("stats:%s:%s", month, k)
		val, _ := p.ctx.Store.Get(key)
		if val != nil {
			stats[k] = val
		}
	}

	writeJSON(w, 200, map[string]any{
		"data": map[string]any{
			"current_month": month,
			"stats":         stats,
		},
	})
}

// ─── Helpers ────────────────────────────────────────────────────────────────

func (p *CommentGuard) getString(key string) string {
	v := p.ctx.Settings.Get(key)
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func (p *CommentGuard) getInt(key string, def int) int {
	v := p.ctx.Settings.Get(key)
	if v == nil {
		return def
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	}
	return def
}

func (p *CommentGuard) getBool(key string) bool {
	v := p.ctx.Settings.Get(key)
	if v == nil {
		return false
	}
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true" || b == "1"
	case float64:
		return b != 0
	}
	return false
}

func (p *CommentGuard) checkBlockedWords(content string) (blocked bool, word string) {
	wordsStr := p.getString("blocked_words")
	if wordsStr == "" {
		return false, ""
	}
	lower := strings.ToLower(content)
	for _, w := range strings.FieldsFunc(wordsStr, func(r rune) bool { return r == ',' || r == '，' }) {
		w = strings.TrimSpace(w)
		if w != "" && strings.Contains(lower, strings.ToLower(w)) {
			return true, w
		}
	}
	return false, ""
}

func (p *CommentGuard) checkRateLimit(identifier string, maxPerMinute int) bool {
	minute := time.Now().Unix() / 60
	key := fmt.Sprintf("rate:%s:%d", identifier, minute)
	current, _ := p.ctx.Store.Increment(key)
	return current <= int64(maxPerMinute)
}

func (p *CommentGuard) recordBlock(reason string) {
	now := time.Now()
	month := fmt.Sprintf("%d-%02d", now.Year(), now.Month())
	_, _ = p.ctx.Store.Increment(fmt.Sprintf("stats:%s:blocked", month))
	_, _ = p.ctx.Store.Increment(fmt.Sprintf("stats:%s:blocked:%s", month, reason))
}

func (p *CommentGuard) recordPass() {
	now := time.Now()
	month := fmt.Sprintf("%d-%02d", now.Year(), now.Month())
	_, _ = p.ctx.Store.Increment(fmt.Sprintf("stats:%s:passed", month))
}

func truncateStr(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

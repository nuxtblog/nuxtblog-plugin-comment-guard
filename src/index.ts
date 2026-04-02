/**
 * nuxtblog/comment-guard — 评论防护
 *
 * 展示能力:
 *  - filter chain (comment.create / comment.update / user.login)
 *  - pipeline (AI 审核 + webhook 通知)
 *  - nuxtblog.store (速率限制 + 统计)
 *  - nuxtblog.ai (垃圾评论检测)
 *  - nuxtblog.emit (插件间通信)
 *  - nuxtblog.on (事件监听)
 *  - 自定义路由 (统计 API)
 *  - activationEvents 按需激活
 */

// ── 生命周期 ─────────────────────────────────────────────────────────────────

export function activate(ctx: PluginContext): void {
  nuxtblog.log.info('Comment Guard activated')

  // ── Filter: 评论创建前 ──────────────────────────────────────────────────

  ctx.subscriptions.push(
    nuxtblog.filter('comment.create', (ctx) => {
      const content = (ctx.data.content as string) || ''
      const authorEmail = (ctx.data.author_email as string) || ''

      // 1) 最短长度检查
      const minLen = (nuxtblog.settings.get('min_content_length') as number) || 5
      if (content.trim().length < minLen) {
        recordBlock('too_short')
        ctx.abort(`评论内容太短，至少需要 ${minLen} 个字符`)
        return
      }

      // 2) 屏蔽词检查
      const blockedWordsStr = (nuxtblog.settings.get('blocked_words') as string) || ''
      if (blockedWordsStr) {
        const blockedWords = blockedWordsStr.split(/[,，]/).map(w => w.trim()).filter(Boolean)
        const lowerContent = content.toLowerCase()
        for (const word of blockedWords) {
          if (lowerContent.includes(word.toLowerCase())) {
            recordBlock('blocked_word')
            ctx.abort(`评论包含屏蔽词: ${word}`)
            return
          }
        }
      }

      // 3) 速率限制
      const rateLimit = (nuxtblog.settings.get('rate_limit') as number) || 5
      const rateLimitPassed = checkRateLimit(authorEmail, rateLimit)
      if (!rateLimitPassed) {
        recordBlock('rate_limit')
        ctx.abort('评论过于频繁，请稍后再试')
        return
      }

      // 4) 简单规则：过多链接 (> 3) → 可疑
      const linkCount = (content.match(/https?:\/\//g) || []).length
      if (linkCount > 3) {
        recordBlock('too_many_links')
        ctx.abort('评论包含过多链接')
        return
      }

      // 5) 标记是否需要 AI 审核（由 pipeline 异步执行）
      const aiReview = nuxtblog.settings.get('ai_review') as boolean
      if (aiReview) {
        // 启发式：纯英文评论在中文博客上 + 含链接 → 大概率垃圾
        const hasChinese = /[\u4e00-\u9fff]/.test(content)
        const hasLinks = linkCount > 0
        if (!hasChinese && hasLinks) {
          ctx.meta['needs_ai_review'] = true
        }
      }

      // 通过所有检查
      recordPass()
    })
  )

  // ── Filter: 评论编辑前 ──────────────────────────────────────────────────

  ctx.subscriptions.push(
    nuxtblog.filter('comment.update', (ctx) => {
      const content = (ctx.data.content as string) || ''

      // 屏蔽词检查（编辑时也要检查）
      const blockedWordsStr = (nuxtblog.settings.get('blocked_words') as string) || ''
      if (blockedWordsStr) {
        const blockedWords = blockedWordsStr.split(/[,，]/).map(w => w.trim()).filter(Boolean)
        const lowerContent = content.toLowerCase()
        for (const word of blockedWords) {
          if (lowerContent.includes(word.toLowerCase())) {
            recordBlock('blocked_word_edit')
            ctx.abort(`评论包含屏蔽词: ${word}`)
            return
          }
        }
      }
    })
  )

  // ── Filter: 登录前 — IP 封禁检查 ────────────────────────────────────────

  ctx.subscriptions.push(
    nuxtblog.filter('user.login', (ctx) => {
      const email = (ctx.data.email as string) || ''

      // 检查是否是已知的垃圾邮箱域
      const spamDomains = ['tempmail.com', 'guerrillamail.com', 'mailinator.com']
      const emailDomain = email.split('@')[1]?.toLowerCase()
      if (emailDomain && spamDomains.includes(emailDomain)) {
        ctx.abort('此邮箱域名已被封禁')
        return
      }
    })
  )

  // ── Event: 评论被审核通过 — 记录好用户 ──────────────────────────────────

  ctx.subscriptions.push(
    nuxtblog.on('comment.approved', (data) => {
      // 记录此用户为可信用户
      if (data.moderator_id) {
        nuxtblog.store.increment('stats:approved')
      }
    })
  )

  // ── Event: 监听其他插件的信号 ───────────────────────────────────────────

  ctx.subscriptions.push(
    nuxtblog.on('ai-polish:result-ready' as any, (data: any) => {
      // 可以对 AI 润色的结果做额外处理
      nuxtblog.log.debug(`Received AI polish result for post ${data.postId}`)
    })
  )
}

export function deactivate(): void {
  nuxtblog.log.info('Comment Guard deactivated')
}

// ── 速率限制 ─────────────────────────────────────────────────────────────────

function checkRateLimit(identifier: string, maxPerMinute: number): boolean {
  const minute = Math.floor(Date.now() / 60000).toString()
  const key = `rate:${identifier}:${minute}`
  const current = nuxtblog.store.increment(key)
  return current <= maxPerMinute
}

// ── 统计记录 ─────────────────────────────────────────────────────────────────

function recordBlock(reason: string): void {
  const month = new Date().toISOString().slice(0, 7)
  nuxtblog.store.increment(`stats:${month}:blocked`)
  nuxtblog.store.increment(`stats:${month}:blocked:${reason}`)

  // 发出自定义事件，其他插件可以监听
  nuxtblog.emit('comment-guard:blocked', { reason, timestamp: Date.now() })
}

function recordPass(): void {
  const month = new Date().toISOString().slice(0, 7)
  nuxtblog.store.increment(`stats:${month}:passed`)
}

// ── Pipeline 步骤: AI 垃圾检测 ───────────────────────────────────────────

export function pipelineAICheck(ctx: StepContext): void {
  const content = ctx.data.content as string
  const authorName = ctx.data.author_name as string

  nuxtblog.log.info(`Running AI spam check for comment by ${authorName}`)

  const result = nuxtblog.ai.polish(
    `判断以下评论是否是垃圾评论。回复 "spam" 或 "not_spam"：\n\n${content}`,
  )

  if (result.ok && result.text) {
    const isSpam = result.text.toLowerCase().includes('spam') && !result.text.toLowerCase().includes('not_spam')
    ctx.meta['is_spam'] = isSpam
    ctx.meta['ai_verdict'] = result.text

    if (isSpam) {
      nuxtblog.log.warn(`AI flagged comment as spam: "${content.slice(0, 50)}..."`)
      recordBlock('ai_spam')

      // 发出事件，其他插件可以监听并做额外处理
      nuxtblog.emit('comment-guard:spam-detected', {
        commentId: ctx.data.id as number,
        content,
        authorName,
        aiVerdict: result.text,
      })
    }
  }
}

export function pipelineLogSkip(_ctx: StepContext): void {
  nuxtblog.log.debug('AI review not needed for this comment')
}

// ── 路由: GET /api/plugin/comment-guard/stats ──────────────────────────────

export function handleGetStats(req: PluginRequest): PluginResponse {
  const month = req.query['month'] || new Date().toISOString().slice(0, 7)

  const keys = nuxtblog.store.list(`stats:${month}:`)
  const values = nuxtblog.store.getMany(keys)

  const stats: Record<string, number> = {}
  for (const [k, v] of Object.entries(values)) {
    const shortKey = k.replace(`stats:${month}:`, '')
    stats[shortKey] = v as number
  }

  // 历史月份汇总
  const allMonths = nuxtblog.store.list('stats:')
  const months = [...new Set(allMonths.map(k => {
    const m = k.match(/^stats:(\d{4}-\d{2}):/)
    return m ? m[1] : null
  }).filter(Boolean))]

  return {
    status: 200,
    body: {
      data: {
        current_month: month,
        stats,
        available_months: months,
      }
    }
  }
}

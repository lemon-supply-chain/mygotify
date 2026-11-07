# MyGotify

**English** | [中文](#中文)

MyGotify brings Spotify's catalog, your library and its recommendations to [MyGo Music](https://github.com/egoist/mygo-music), and plays the audio from YouTube Music. It isn't affiliated with or endorsed by Spotify, YouTube, or Google, uses private APIs, and may stop working at any time.

## Why MyGotify

- **No Premium, no ads.** Browse with Spotify and listen through YouTube Music, with nothing between songs.
- **Lyrics for more songs.** When Spotify has no timed lyrics, MyGotify looks on [LRCLIB](https://lrclib.net/) and then [NetEase Cloud Music (网易云音乐)](https://music.163.com/), which covers far more Chinese, Japanese and Korean songs. Lyrics that come without times still scroll with the song.
- **Your Spotify, all of it.** Your playlists, liked songs, saved albums, followed artists, and Made For You: Daily Mixes, Discover Weekly, Release Radar and your top mixes.
- **Works without an account.** Search, albums, artists, playlists, radio and lyrics need no sign-in.
- **The right recording.** Each song is matched on YouTube Music by title, artists and length, and the match is remembered, so it starts faster next time.
- **Your listening stays yours.** What you play here never reaches your Spotify history; Recently Played is kept on your machine.
- **Speaks Chinese.** The plugin's interface is translated into Simplified Chinese.

## Install

Install [ffmpeg](https://ffmpeg.org), and [yt-dlp](https://github.com/yt-dlp/yt-dlp) as a fallback. On macOS:

```bash
brew install ffmpeg yt-dlp
```

yt-dlp needs a JavaScript runtime (Deno, Node or Bun) to solve YouTube's challenges; Homebrew includes Deno. Keep yt-dlp up to date, as YouTube changes often.

Install with the deeplink:

[mygo-music://install-plugin?repo=r0k1s-i/mygotify](mygo-music://install-plugin?repo=r0k1s-i/mygotify)

Or paste the GitHub URL in Settings > Plugins.

In Settings > Plugins, allow MyGotify to start programs. To get your library, click **Sign In** and sign in to Spotify in the window that opens.

It needs MyGo Music 0.1.8 or later, and only starts ffmpeg and yt-dlp: from the PATH, `/opt/homebrew/bin` or `/usr/local/bin`. If they're somewhere else, link them into one of those.

## Signing in

You sign in on Spotify's login page, in a window of the app. The session cookie (`sp_dc`) is stored unencrypted in the plugin's data on this machine and is used to obtain web player access tokens. Signing out forgets it.

On Linux, the app aborts when a plugin opens its sign-in window, so sign in with the cookie instead: sign in at [open.spotify.com](https://open.spotify.com) in your browser, copy the value of the `sp_dc` cookie from its developer tools (Storage > Cookies), paste it in Settings > Plugins > MyGotify, and click **Sign In**. A cookie pasted there is used on other platforms too, without the window. Changing it signs you out.

## What works

- Signed out: playing, Home, search (tracks, albums, artists, playlists), albums, artists, playlists, radio stations, and lyrics.
- Signed in: your playlists, liked songs, saved albums, followed artists, Made For You (Daily Mixes, Discover Weekly, Release Radar and your top mixes), liking/unliking songs, saving/unsaving albums, following/unfollowing artists, and saving/unsaving playlists.
- Recently Played lists the last 50 songs played in MyGo Music, kept on this machine. The app keeps a sidebar page once loaded, so for songs played since, open My Page from the account menu, which loads anew each time.
- Not available: creating or reordering playlist tracks, and podcast episodes.

## How it plays

Spotify track metadata (title, artists, duration) is matched against YouTube Music songs using Innertube search and scored based on duration delta and metadata similarity. Audio is fetched as YouTube's Vision Pro app asks for it, then ffmpeg converts it to MP3 on the fly. If that fails, yt-dlp is used as a fallback. Mappings between Spotify tracks and YouTube videos are cached in plugin storage.

## Lyrics

From Spotify color-lyrics when they are timed, with an automatic fallback chain: LRCLIB exact match, LRCLIB search, and NetEase Cloud Music by title, artist, and duration. Lyrics without times, when no source has timed ones, are spread evenly over the song.

## Credits and License

- Spotify Web Player authentication, TOTP generation, and Pathfinder GraphQL queries ported from [sonic-liberation/spotube-plugin-spotify](https://github.com/sonic-liberation/spotube-plugin-spotify) (AGPL-3.0).
- YouTube Music Innertube search, VisionOS player integration, and ffmpeg/yt-dlp streaming pipeline adapted from [egoist/mygo-music-youtube-music](https://github.com/egoist/mygo-music-youtube-music) by egoist. That repository states no license, so this part is used with credit but is not relicensed here; ask its author before redistributing.
- Licensed under [AGPL-3.0](LICENSE).

---

## 中文

[English](#mygotify) | **中文**

MyGotify 把 Spotify 的曲库、你的音乐库和推荐带进 [MyGo Music](https://github.com/egoist/mygo-music)，音频则来自 YouTube Music。本插件与 Spotify、YouTube、Google 均无关联，也未获其认可；它使用的是非公开接口，随时可能失效。

### 亮点

- **不用 Premium，没有广告。** 用 Spotify 找歌，用 YouTube Music 播放，歌与歌之间没有任何插播。
- **歌词更全。** Spotify 没有逐行歌词时，会依次去 [LRCLIB](https://lrclib.net/) 和[网易云音乐](https://music.163.com/)找，华语、日语、韩语歌曲的覆盖率高得多。只有纯文本、没有时间轴的歌词，也会跟着歌曲滚动。
- **完整的 Spotify。** 你的歌单、喜欢的歌曲、收藏的专辑、关注的艺人，以及“为你推荐”：每日推荐（Daily Mix）、每周新发现（Discover Weekly）、新歌雷达（Release Radar）和你的常听合集。
- **不登录也能用。** 搜索、专辑、艺人、歌单、电台和歌词都不需要账号。
- **匹配准确。** 每首歌按歌名、艺人和时长在 YouTube Music 上匹配，匹配结果会被记住，下次播放更快。
- **听歌记录留在本地。** 在这里播放的歌曲不会进入你的 Spotify 播放历史；“最近播放”只保存在你的电脑上。
- **中文界面。** 插件界面已翻译为简体中文。

### 安装

先安装 [ffmpeg](https://ffmpeg.org)，并安装 [yt-dlp](https://github.com/yt-dlp/yt-dlp) 作为备用。macOS 上：

```bash
brew install ffmpeg yt-dlp
```

yt-dlp 需要一个 JavaScript 运行时（Deno、Node 或 Bun）来通过 YouTube 的验证，Homebrew 会一起装上 Deno。YouTube 经常变动，请保持 yt-dlp 为最新版本。

点击深链接安装：

[mygo-music://install-plugin?repo=r0k1s-i/mygotify](mygo-music://install-plugin?repo=r0k1s-i/mygotify)

或者在 设置 > 插件 中粘贴本仓库的 GitHub 地址。

然后在 设置 > 插件 中允许 MyGotify 启动程序。要读取你的音乐库，点击 **登录**，在弹出的窗口里登录 Spotify。

需要 MyGo Music 0.1.8 或更高版本。插件只会启动 ffmpeg 和 yt-dlp，且只从 PATH、`/opt/homebrew/bin` 或 `/usr/local/bin` 中查找。如果装在别处，请把它们链接到其中一个目录。

### 登录

登录在应用内的一个窗口里、通过 Spotify 自己的登录页完成。会话 Cookie（`sp_dc`）以明文保存在本机的插件数据中，用于获取网页播放器的访问令牌。退出登录会删除它。

在 Linux 上，插件打开登录窗口会导致应用崩溃，所以请改用 Cookie 登录：在浏览器里登录 [open.spotify.com](https://open.spotify.com)，从开发者工具（存储 > Cookie）中复制 `sp_dc` 的值，粘贴到 设置 > 插件 > MyGotify，再点击 **登录**。其他系统上也可以这样做，就不会弹出窗口。修改 Cookie 会让你退出登录。

### 功能

- 未登录：播放、首页、搜索（歌曲、专辑、艺人、歌单）、专辑、艺人、歌单、电台和歌词。
- 已登录：你的歌单、喜欢的歌曲、收藏的专辑、关注的艺人、为你推荐（每日推荐、每周新发现、新歌雷达和常听合集），以及喜欢/取消喜欢歌曲、收藏/取消收藏专辑、关注/取消关注艺人、收藏/取消收藏歌单。
- “最近播放”列出在 MyGo Music 中播放的最近 50 首歌，保存在本机。侧边栏页面加载后不会自动刷新，想看之后播放的歌曲，请从账户菜单打开“我的主页”，它每次都会重新加载。
- 暂不支持：新建歌单、调整歌单内歌曲顺序，以及播客。

### 播放原理

用 Spotify 的歌曲信息（歌名、艺人、时长）通过 Innertube 搜索 YouTube Music，按时长差和信息相似度打分挑出最佳匹配。音频以 YouTube Vision Pro 应用的方式获取，再由 ffmpeg 实时转成 MP3；失败时改用 yt-dlp。Spotify 歌曲与 YouTube 视频的对应关系缓存在插件存储中。

### 歌词

优先使用 Spotify 的逐行歌词（color-lyrics）；没有时依次尝试：LRCLIB 精确匹配、LRCLIB 搜索、按歌名、艺人和时长搜索网易云音乐。如果所有来源都没有带时间轴的歌词，纯文本歌词会平均分布在整首歌的时长上。

### 致谢与许可

- Spotify 网页播放器认证、TOTP 生成和 Pathfinder GraphQL 查询移植自 [sonic-liberation/spotube-plugin-spotify](https://github.com/sonic-liberation/spotube-plugin-spotify)（AGPL-3.0）。
- YouTube Music Innertube 搜索、VisionOS 播放器集成以及 ffmpeg/yt-dlp 串流流程改编自 egoist 的 [egoist/mygo-music-youtube-music](https://github.com/egoist/mygo-music-youtube-music)。该仓库未声明许可证，因此这部分代码仅注明出处使用，不在此重新授权；再分发前请先征得原作者同意。
- 本项目以 [AGPL-3.0](LICENSE) 许可发布。

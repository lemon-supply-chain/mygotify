# Spotify for MyGo Music

Plays Spotify in [MyGo Music](https://github.com/egoist/mygo-music) with audio provided via YouTube Music. It isn't affiliated with or endorsed by Spotify, YouTube, or Google, uses private APIs, and may stop working at any time.

## Install

Install [ffmpeg](https://ffmpeg.org), and [yt-dlp](https://github.com/yt-dlp/yt-dlp) as a fallback. On macOS:

```bash
brew install ffmpeg yt-dlp
```

yt-dlp needs a JavaScript runtime (Deno, Node or Bun) to solve YouTube's challenges; Homebrew includes Deno. Keep yt-dlp up to date, as YouTube changes often.

Install with the deeplink:

[mygo-music://install-plugin?repo=r0k1s_i/mygo-music-spotube](mygo-music://install-plugin?repo=r0k1s_i/mygo-music-spotube)

Or paste the GitHub URL in Settings > Plugins.

In Settings > Plugins, allow Spotify to start programs. To get your library, click **Sign In** and sign in to Spotify in the window that opens.

It needs MyGo Music 0.1.8 or later, and only starts ffmpeg and yt-dlp: from the PATH, `/opt/homebrew/bin` or `/usr/local/bin`. If they're somewhere else, link them into one of those.

## Signing in

You sign in on Spotify's login page, in a window of the app. The session cookie (`sp_dc`) is stored unencrypted in the plugin's data on this machine and is used to obtain web player access tokens. Signing out forgets it.

On Linux, the app aborts when a plugin opens its sign-in window, so sign in with the cookie instead: sign in at [open.spotify.com](https://open.spotify.com) in your browser, copy the value of the `sp_dc` cookie from its developer tools (Storage > Cookies), paste it in Settings > Plugins > Spotify, and click **Sign In**. A cookie pasted there is used on other platforms too, without the window. Changing it signs you out.

## What works

- Signed out: playing, Home, search (tracks, albums, artists, playlists), albums, artists, playlists, radio stations, and timed lyrics.
- Signed in: your playlists, liked songs, liking/unliking songs, saving/unsaving albums, following/unfollowing artists, and saving/unsaving playlists.
- Not available: creating or reordering playlist tracks, and podcast episodes.

## How it plays

Spotify track metadata (title, artists, duration) is matched against YouTube Music songs using Innertube search and scored based on duration delta and metadata similarity. Audio is fetched as YouTube's Vision Pro app asks for it, then ffmpeg converts it to MP3 on the fly. If that fails, yt-dlp is used as a fallback. Mappings between Spotify tracks and YouTube videos are cached in plugin storage.

## Lyrics

From Spotify color-lyrics when available, with an automatic fallback chain: [LRCLIB](https://lrclib.net/) exact match, LRCLIB search, and [NetEase Cloud Music (网易云音乐)](https://music.163.com/) by title, artist, and duration.

## Credits and License

- Spotify Web Player authentication, TOTP generation, and Pathfinder GraphQL queries ported from [sonic-liberation/spotube-plugin-spotify](https://github.com/sonic-liberation/spotube-plugin-spotify) (AGPL-3.0).
- YouTube Music Innertube search, VisionOS player integration, and ffmpeg/yt-dlp streaming pipeline adapted from [egoist/mygo-music-youtube-music](https://github.com/egoist/mygo-music-youtube-music) by egoist. That repository states no license, so this part is used with credit but is not relicensed here; ask its author before redistributing.
- Licensed under [AGPL-3.0](LICENSE).

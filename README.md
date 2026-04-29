# Angkor Proxy

<p align="center">
  <img src="https://i.imgur.com/angkor.png" alt="Angkor Logo" width="200"/>
</p>

<p align="center">
  <strong>Advanced Minecraft Velocity Proxy with Security, Anti-DDoS, and AntiCheat Modules</strong>
</p>

<p align="center">
  <a href="https://github.com/boykisser-clan/angkor/releases"><img src="https://img.shields.io/github/v/release/boykisser-clan/angkor?style=flat-square" alt="Release"/></a>
  <a href="https://github.com/boykisser-clan/angkor/blob/main/LICENSE"><img src="https://img.shields.io/github/license/boykisser-clan/angkor?style=flat-square" alt="License"/></a>
  <a href="https://github.com/boykisser-clan/angkor/issues"><img src="https://img.shields.io/github/issues/boykisser-clan/angkor?style=flat-square" alt="Issues"/></a>
</p>

---

## Features

### Security Module
- **Reconnect Checker** - Prevents replay attacks with token-based verification
- **VPN/Proxy Detection** - Blocks connections from VPNs and proxy services
- **Account Validation** - Premium/cracked account checking with caching
- **Packet Rate Limiter** - Prevents packet flooding attacks

### Anti-DDoS Protection
- **UDP Flood Detection** - Monitors and blocks UDP flood attacks
- **Connection Rate Limiting** - Per-IP connection throttling
- **Slow Server Protection** - Automatically reduces connections during TPS drops
- **Iptables Integration** - Optional firewall-level blocking

### AntiCheat System
- **Command Monitoring** - Detects suspicious commands (OP abuse, backdoors, exploits)
- **Chat Prefix Monitoring** - Monitors dot commands and special prefixes (`.`, `#`, `$`, `!`, `//`, `->`, `>>`, `::`, `&&`)
- **Player Whitelist** - Bypass system for trusted players with webhook notifications
- **Active Blocking** - Blocks suspicious commands for non-whitelisted players
- **Discord Webhooks** - Real-time alerts with color-coded embeds and SmallCaps styling
- **Violation Tracking** - Tracks player violations with configurable thresholds

## Installation

1. Download the latest `angkor.jar` from [Releases](https://github.com/boykisser-clan/angkor/releases)
2. Place it in your Velocity proxy's `plugins` folder
3. Start your proxy to generate default `angkor.yml`
4. Configure the settings and restart

## Configuration

Edit `angkor.yml` in your Velocity configuration directory:

```yaml
angkor:
  security:
    reconnect-check:
      enabled: true
      expire-pending-minutes: 5
      verified-ttl-minutes: 30
      kick-message: "&eAngkor Anti-Bot: Please reconnect to verify."
    vpn-check:
      enabled: true
      api-key: "YOUR_API_KEY_HERE"
      action: KICK
      kick-message: "&cVPN/Proxy not allowed."
    account-check:
      enabled: true
      allow-cracked: false
      kick-message: "&cInvalid Minecraft account."
    packet-limiter:
      enabled: true
      threshold: 500
      throttle-seconds: 60

  ddos:
    udp-protection:
      enabled: true
      threshold-pps: 100
      block-duration-seconds: 300
      use-iptables: true
    connection-limiter:
      enabled: true
      max-connections-per-second: 10
      violations-before-ban: 5
      ban-duration-seconds: 300
    slow-server-protection:
      enabled: true
      response-threshold-ms: 200
      recovery-threshold-ms: 100
      recovery-checks: 3
      slow-mode-max-connections: 3

  anticheat:
    enabled: true
    log-to-console: true
    monitor-dot-commands: true
    monitor-auth-commands: true
    webhook:
      enabled: true
      url: "YOUR_DISCORD_WEBHOOK_URL_HERE"
      batch-interval-seconds: 3
      batch-size: 5
    whitelist:
      log-whitelisted-to-webhook: true
      uuids:
        - "00000000-0000-0000-0000-000000000000"
      usernames:
        - "YourAdminName"
    custom-watched-commands:
      - "/vanish"
      - "/invsee"
      - "/noclip"
      - "/fly"
      - "/speed"
      - "/gamemode"

  whitelist-ips:
    - "127.0.0.1"
    - "::1"
    - "localhost"
```

## Important Notes

- **Login commands** (`/login`, `/nlogin`, `/l`, `/log`, `/blogin`) are NEVER logged or blocked
- **`/give` command** is intentionally NOT monitored
- **Whitelisted players** bypass command blocking but still trigger webhook alerts
- Webhook embeds use **SmallCapsConverter** for stylized text (player names and commands remain original)

## Building from Source

```bash
git clone https://github.com/boykisser-clan/angkor.git
cd angkor
JAVA_HOME=/path/to/jdk-21 ./gradlew build -x checkstyleMain -x checkstyleTest
```

Output jar: `proxy/build/libs/angkor.jar`

## Credits

- **Author**: RIN (Kimsathh)
- **Organization**: boykisser-clan
- **Studio**: Krud Studio
- **Based on**: Velocity Proxy by Velocity Contributors

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/kimsathh">RIN</a> @ <a href="https://github.com/boykisser-clan">boykisser-clan</a> | <a href="https://krud.studio">Krud Studio</a></sub>
</p>

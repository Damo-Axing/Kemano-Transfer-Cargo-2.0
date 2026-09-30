#ifndef KTC_H
#define KTC_H

#include <stdint.h>
#include <stddef.h>

/* --- Версия протокола --- */

#define KTC_VERSION_MAJOR 2
#define KTC_VERSION_MINOR 0
#define KTC_VERSION_PATCH 0
#define KTC_VERSION 0x00020000

/* --- Размеры пакетов --- */

#define KTC0_SIZE 156
#define KTCA_SIZE 108

/* --- Размеры ключей --- */

#define ROOT_KEY_SIZE 32
#define HANDSHAKE_KEY_SIZE 32
#define LEGEND_KEY_SIZE 32
#define SESSION_KEY_SIZE 32
#define X25519_KEY_SIZE 32
#define DEVICE_SECRET_SIZE 32

/* --- Размеры полей --- */

#define TPM_QUOTE_SIZE 32
#define HW_MAC_PROOF_SIZE 32
#define LEGEND_SIG_SIZE 24
#define SERVER_PROOF_SIZE 32
#define POLY1305_TAG_SIZE 16
#define NONCE_SIZE 12

/* --- Ограничения --- */

#define MAX_PAYLOAD 65535
#define MAX_STREAMS 8
#define MAX_SACK_RANGES 128
#define MAX_CLIENTS 4096
#define MAX_SESSIONS 1024
#define RECV_BUF_SIZE 65535

/* --- Таймауты (мс) --- */

#define TIMESTAMP_WINDOW_MS 30000
#define SILENCE_TIMEOUT_MS 30000
#define ALIVE_INTERVAL_MIN_MS 15000
#define ALIVE_INTERVAL_MAX_MS 25000
#define SACK_INTERVAL_FRAMES 16
#define SACK_INTERVAL_MS 10
#define HANDSHAKE_TIMEOUT_MS 5000
#define BBR_PROBE_RTT_SEC 10

/* --- Frame Flags --- */

#define FLAG_EXT_LENGTH   0x01
#define FLAG_COMPRESSED   0x02
#define FLAG_SACK         0x04
#define FLAG_MASK_TRIGGER 0x08
#define FLAG_HALT         0x10
#define FLAG_ALIVE        0x20

/* --- Stream IDs --- */

#define STREAM_CONTROL  0
#define STREAM_DATA_MIN 1
#define STREAM_DATA_MAX 7

/* --- Mask Profiles --- */

#define PROFILE_RAW            0
#define PROFILE_YOUTUBE_LIVE   1
#define PROFILE_ZOOM_VIDEO     2
#define PROFILE_DISCORD_VOICE  3
#define PROFILE_WEBRTC         4
#define PROFILE_HTTPS_CDN      5
#define PROFILE_DNS_HTTPS      6
#define PROFILE_STEAM_DL       7
#define PROFILE_STUN           8
#define PROFILE_HTTP3_QUIC     9
#define PROFILE_CLOUDFLARE     10
#define PROFILE_GOOGLE_QUIC    11

#endif /* KTC_H */

/*
 * Copyright (C) 2026 Velocity Contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/**
 * Sends alerts to Discord via webhook.
 * Supports batching to avoid rate limits.
 */
public class DiscordWebhookSender {

    private static final Logger logger = Logger.getLogger("Angkor-Webhook");

    private final ConcurrentLinkedQueue<SuspiciousCommand> pendingAlerts = new ConcurrentLinkedQueue<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final java.util.concurrent.ExecutorService webhookExecutor = Executors.newSingleThreadExecutor();

    private String webhookUrl = "";
    private int batchIntervalSeconds = 3;
    private int batchSize = 5;
    private boolean enabled = false;

    /**
     * Creates a new DiscordWebhookSender.
     */
    public DiscordWebhookSender() {
        scheduler.scheduleAtFixedRate(this::flushQueue, batchIntervalSeconds, batchIntervalSeconds, TimeUnit.SECONDS);
    }

    /**
     * Sets the webhook URL.
     *
     * @param url the Discord webhook URL
     */
    public void setWebhookUrl(String url) {
        this.webhookUrl = url;
    }

    /**
     * Sets the batch interval in seconds.
     *
     * @param seconds the interval between batch sends
     */
    public void setBatchIntervalSeconds(int seconds) {
        this.batchIntervalSeconds = seconds;
    }

    /**
     * Sets the batch size (max alerts before immediate send).
     *
     * @param size the batch size
     */
    public void setBatchSize(int size) {
        this.batchSize = size;
    }

    /**
     * Sets whether the webhook sender is enabled.
     *
     * @param enabled true to enable, false to disable
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Sends an alert to Discord.
     * Adds to queue and triggers immediate flush if queue size >= batch size.
     *
     * @param cmd the suspicious command to alert
     */
    public void sendAlert(SuspiciousCommand cmd) {
        if (!enabled || webhookUrl.isEmpty()) {
            return;
        }

        pendingAlerts.add(cmd);

        if (pendingAlerts.size() >= batchSize) {
            flushQueue();
        }
    }

    /**
     * Flushes the queue and sends all pending alerts.
     * If multiple alerts, sends as a single batch embed.
     * If single alert, sends as individual embed.
     */
    private void flushQueue() {
        if (pendingAlerts.isEmpty()) {
            return;
        }

        List<SuspiciousCommand> toSend = new ArrayList<>();
        int count = pendingAlerts.size();
        for (int i = 0; i < count && !pendingAlerts.isEmpty(); i++) {
            SuspiciousCommand cmd = pendingAlerts.poll();
            if (cmd != null) {
                toSend.add(cmd);
            }
        }

        if (toSend.isEmpty()) {
            return;
        }

        webhookExecutor.submit(() -> {
            String jsonPayload;
            if (toSend.size() == 1) {
                jsonPayload = WebhookPayloadBuilder.buildSingleAlert(toSend.get(0));
            } else {
                jsonPayload = WebhookPayloadBuilder.buildBatchAlert(toSend);
            }
            sendToWebhook(jsonPayload);
        });
    }

    /**
     * Sends the startup notification to Discord.
     */
    public void sendStartupNotification() {
        if (!enabled || webhookUrl.isEmpty()) {
            return;
        }
        webhookExecutor.submit(() -> {
            String payload = WebhookPayloadBuilder.buildStartup();
            sendToWebhook(payload);
        });
    }

    /**
     * Sends the shutdown notification to Discord.
     */
    public void sendShutdownNotification() {
        if (!enabled || webhookUrl.isEmpty()) {
            return;
        }
        webhookExecutor.submit(() -> {
            String payload = WebhookPayloadBuilder.buildShutdown();
            sendToWebhook(payload);
        });
    }

    /**
     * Sends a JSON payload to the Discord webhook URL.
     * Handles HTTP 429 rate limiting with one retry.
     *
     * @param jsonPayload the JSON payload to send
     */
    private void sendToWebhook(String jsonPayload) {
        try {
            sendToWebhookInternal(jsonPayload, 0);
        } catch (Exception e) {
            logger.warning("[Angkor-Webhook] Failed to send alert: " + e.getMessage());
        }
    }

    private void sendToWebhookInternal(String jsonPayload, int retryCount) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(webhookUrl).openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonPayload.getBytes("UTF-8"));
            os.flush();
        }

        int responseCode = conn.getResponseCode();

        if (responseCode == 204 || responseCode == 200) {
            return; // Success
        }

        if (responseCode == 429 && retryCount == 0) {
            // Rate limited - parse retry_after and retry
            String retryAfterStr = conn.getHeaderField("Retry-After");
            if (retryAfterStr != null) {
                try {
                    long retryAfter = Long.parseLong(retryAfterStr) * 1000;
                    Thread.sleep(retryAfter);
                    sendToWebhookInternal(jsonPayload, 1);
                    return;
                } catch (Exception e) {
                    // ignore and log
                }
            }
        }

        // Read error response
        StringBuilder error = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(conn.getErrorStream()))) {
            String line;
            while ((line = br.readLine()) != null) {
                error.append(line);
            }
        }
        logger.warning("[Angkor-Webhook] Failed to send alert: " + responseCode + " - " + error.toString());
    }

    /**
     * Shuts down the webhook sender, flushing remaining queue.
     */
    public void shutdown() {
        flushQueue(); // Send any remaining alerts
        scheduler.shutdown();
        webhookExecutor.shutdown();
    }
}

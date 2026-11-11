<?php
/** CLI-only byte-preserving DISABLE_WP_CRON plan; never evaluate wp-config.php. */
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
function wordpriis_cron_config_plan(string $source, bool $disabled = true): array {
    $tokens = []; $offset = 0;
    foreach (token_get_all($source) as $token) {
        $text = is_array($token) ? $token[1] : $token;
        if (!is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            $tokens[] = ['id' => is_array($token) ? $token[0] : null, 'text' => $text, 'offset' => $offset];
        }
        $offset += strlen($text);
    }
    $defines = []; $anchor = null; $depth = 0;
    for ($i = 0; $i < count($tokens); $i++) {
        $t = $tokens[$i]; $text = $t['text'];
        if ($t['id'] === T_EVAL) { throw new RuntimeException('dynamic-config-not-supported'); }
        if ($text === '{') { $depth++; } elseif ($text === '}') { $depth--; }
        if (in_array($t['id'], [T_REQUIRE, T_REQUIRE_ONCE, T_INCLUDE, T_INCLUDE_ONCE], true)) {
            if ($depth !== 0) { throw new RuntimeException('dynamic-config-not-supported'); }
            $tail = array_column(array_slice($tokens, $i + 1, 4), 'text');
            if (count($tail) === 4 && $tail[0] === 'ABSPATH' && $tail[1] === '.' && in_array($tail[2], ["'wp-settings.php'", '"wp-settings.php"'], true) && $tail[3] === ';') {
                if ($anchor !== null) { throw new RuntimeException('ambiguous-settings-load'); }
                $anchor = $t['offset'];
            } else { throw new RuntimeException('dynamic-config-not-supported'); }
        }
        if (!in_array(strtolower($text), ['define', '\\define'], true) || ($tokens[$i + 1]['text'] ?? null) !== '(') { continue; }
        $key = $tokens[$i + 2]['text'] ?? '';
        if (($tokens[$i + 2]['id'] ?? null) !== T_CONSTANT_ENCAPSED_STRING || str_contains($key, '\\') || str_contains($key, '$') || ($tokens[$i + 3]['text'] ?? null) !== ',') { throw new RuntimeException('dynamic-config-not-supported'); }
        if (!in_array($key, ["'DISABLE_WP_CRON'", '"DISABLE_WP_CRON"'], true)) { continue; }
        $previous = $tokens[$i - 1] ?? null;
        if ($depth !== 0 || !$previous || !($previous['id'] === T_OPEN_TAG || in_array($previous['text'], [';', '}'], true))
            || ($tokens[$i + 3]['text'] ?? null) !== ',' || !in_array(strtolower($tokens[$i + 4]['text'] ?? ''), ['true','false'], true)
            || ($tokens[$i + 5]['text'] ?? null) !== ')' || ($tokens[$i + 6]['text'] ?? null) !== ';') {
            throw new RuntimeException('complex-cron-define');
        }
        $defines[] = $tokens[$i + 4];
    }
    if ($anchor === null || count($defines) > 1) { throw new RuntimeException('ambiguous-or-unsupported-config'); }
    if ($defines && $defines[0]['offset'] >= $anchor) { throw new RuntimeException('cron-define-after-settings'); }
    if ($defines) {
        $value = $defines[0]; $before = strtolower($value['text']) === 'true';
        $candidate = $before === $disabled ? $source : substr_replace($source, $disabled ? 'true' : 'false', $value['offset'], strlen($value['text']));
    } else {
        $before = null; $newline = str_contains($source, "\r\n") ? "\r\n" : "\n";
        $candidate = !$disabled ? $source : substr_replace($source, "/* WORDPRIIS: request cron replaced by verified Windows task. */{$newline}define( 'DISABLE_WP_CRON', true );{$newline}", $anchor, 0);
    }
    return ['source' => $candidate, 'changed' => $candidate !== $source, 'previous_literal' => $before,
        'original_sha256' => hash('sha256', $source), 'candidate_sha256' => hash('sha256', $candidate)];
}
if (!defined('WORDPRIIS_CRON_CONFIG_LIBRARY_ONLY')) {
    ini_set('display_errors', '0'); ini_set('log_errors', '0');
    try {
        $args = getopt('', ['config:', 'candidate:', 'enable-request-cron', 'diagnose']);
        if (!isset($args['config']) || (!isset($args['diagnose']) && (!isset($args['candidate']) || file_exists($args['candidate'])))) { throw new RuntimeException('invalid-plan-paths'); }
        $plan = wordpriis_cron_config_plan(file_get_contents($args['config']), !isset($args['enable-request-cron']));
        if (isset($args['diagnose'])) {
            echo 'WORDPRIIS_CRON_PLAN:' . json_encode(['status' => 'supported', 'previous_literal' => $plan['previous_literal']], JSON_THROW_ON_ERROR) . PHP_EOL;
            exit;
        }
        $handle = fopen($args['candidate'], 'xb');
        try { if (fwrite($handle, $plan['source']) !== strlen($plan['source'])) { throw new RuntimeException('candidate-write-failed'); } } finally { fclose($handle); }
        unset($plan['source']); echo 'WORDPRIIS_CRON_PLAN:' . json_encode($plan, JSON_THROW_ON_ERROR) . PHP_EOL;
    } catch (Throwable $error) {
        $allowed = ['dynamic-config-not-supported','ambiguous-settings-load','complex-cron-define','ambiguous-or-unsupported-config','cron-define-after-settings','invalid-plan-paths','candidate-write-failed'];
        $code = in_array($error->getMessage(), $allowed, true) ? $error->getMessage() : 'config-plan-failed';
        echo 'WORDPRIIS_CRON_PLAN:' . json_encode(['error' => $code]) . PHP_EOL; exit(1);
    }
}

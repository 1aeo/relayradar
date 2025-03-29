<?php
// Debug flag (set to true to output debug info)
$debug = false;

// Load secrets from a separate file.
$secrets = require_once __DIR__ . '/secrets.php';

// Global AS cache handling.
$cacheFile = __DIR__ . '/as_cache.json';
if (file_exists($cacheFile)) {
    $asCache = json_decode(file_get_contents($cacheFile), true);
    if (!is_array($asCache)) {
        $asCache = [];
    }
} else {
    $asCache = [];
}

/**
 * Outputs overall statistics based on all parsed relays.
 *
 * @param array $relays Array of all relays.
 */
function outputOverallParsingStats($relays) {
    $totalRelays = count($relays);
    
    $fingerprints = [];
    $contacts = [];
    $ipv4Addresses = [];
    
    foreach ($relays as $relay) {
        if (isset($relay['Fingerprint'])) {
            $fingerprints[] = $relay['Fingerprint'];
        } else if (isset($relay['Nickname'])) {
            // fallback: use nickname if fingerprint is not available.
            $fingerprints[] = $relay['Nickname'];
        }
        if (isset($relay['Contact'])) {
            $contacts[] = $relay['Contact'];
        }
        if (isset($relay['IPv4'])) {
            $ipv4Addresses[] = $relay['IPv4'];
        }
    }
    
    $uniqueFingerprints = count(array_unique($fingerprints));
    $uniqueContacts = count(array_unique($contacts));
    $uniqueIPv4 = count(array_unique($ipv4Addresses));
    
    echo "<div style='margin-bottom: 1em;'>";
    echo "<strong># of relays parsed:</strong> " . $totalRelays . "<br>";
    echo "<strong># of unique fingerprints parsed:</strong> " . $uniqueFingerprints . "<br>";
    echo "<strong># of unique contact information parsed:</strong> " . $uniqueContacts . "<br>";
    echo "<strong># of unique IPv4 Addresses parsed:</strong> " . $uniqueIPv4 . "<br>";
    echo "</div>";
}

/**
 * Retrieves the AS information for a given IPv4 address using ipinfo.io.
 * Caches the result in as_cache.json.
 *
 * @param string $ip A valid IPv4 address.
 * @return string The AS information or an error message.
 */
function getASFromIP($ip) {
    global $asCache, $cacheFile, $secrets;
    if (isset($asCache[$ip])) {
        return $asCache[$ip];
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $asCache[$ip] = "Invalid IPv4 address.";
        file_put_contents($cacheFile, json_encode($asCache));
        return $asCache[$ip];
    }
    $token = $secrets['ipinfo_token'];
    $url = "https://ipinfo.io/{$ip}/json?token={$token}";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        $errorMsg = curl_error($ch);
        curl_close($ch);
        $asCache[$ip] = "cURL Error: " . $errorMsg;
        file_put_contents($cacheFile, json_encode($asCache));
        return $asCache[$ip];
    }
    curl_close($ch);
    $data = json_decode($response, true);
    if (isset($data['org'])) {
        $as = $data['org'];
        $asCache[$ip] = $as;
        file_put_contents($cacheFile, json_encode($asCache));
        return $as;
    } else {
        $asCache[$ip] = "AS information not found.";
        file_put_contents($cacheFile, json_encode($asCache));
        return $asCache[$ip];
    }
}

/**
 * Checks if an AS lookup result is valid.
 *
 * @param string $as The AS result.
 * @return bool True if valid; false otherwise.
 */
function hasValidAS($as) {
    $invalids = ["AS information not found.", "Invalid IPv4 address."];
    if (in_array($as, $invalids)) {
        return false;
    }
    if (strpos($as, "cURL Error:") === 0) {
        return false;
    }
    return true;
}

/**
 * Extracts a timestamp from a filename using a regex.
 * Expected filename format: YYYY-MM-DD-HH-MM-SS-server-descriptors
 *
 * @param string $file The filename.
 * @return string The extracted timestamp or an empty string.
 */
function getTimestampFromFilename($file) {
    if (preg_match('/(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})/', $file, $matches)) {
        return $matches[1];
    }
    return "";
}

/**
 * Determines the latest timestamp from an array of filenames.
 *
 * @param array $files Array of filenames.
 * @return string Latest timestamp.
 */
function getLatestFileTimestamp($files) {
    $latest = "";
    foreach ($files as $file) {
        $ts = getTimestampFromFilename($file);
        if ($ts > $latest) {
            $latest = $ts;
        }
    }
    return $latest;
}

/**
 * Parses a single relay descriptor block into an associative array.
 *
 * @param string $block The relay block text.
 * @return array The parsed relay information.
 */
function parseRelayBlock($block) {
    global $debug;
    $lines = explode("\n", $block);
    $relay = [];
    // Initialize ExitRelay flag to false.
    $relay['ExitRelay'] = false;
    
    foreach ($lines as $line) {
        $line = trim($line);
        if (empty($line)) continue;
        
        // Check for "accept" anywhere in the line (ignoring case)
        if (stripos($line, 'accept') !== false) {
            $relay['ExitRelay'] = true;
            if ($debug) {
                echo "<pre>Debug: Found 'accept' in line: '$line'; marking relay as exit.</pre>";
            }
        }
        
        // Process the line by splitting into tokens by whitespace.
        $tokens = preg_split('/\s+/', $line);
        if (empty($tokens)) continue;
        $keyword = strtolower($tokens[0]);
        switch ($keyword) {
            case '@type':
                if ($debug) { echo "<pre>Debug: Skipping @type line.</pre>"; }
                break;
            case 'router':
                // Expected format: router <nickname> <address> <ORPort> <SOCKSPort> <DirPort>
                if (count($tokens) >= 6) {
                    $relay['Nickname'] = $tokens[1];
                    $relay['IPv4'] = $tokens[2];
                    $relay['ORPort'] = $tokens[3];
                    $relay['SOCKSPort'] = $tokens[4];
                    $relay['DirPort'] = $tokens[5];
                    if ($debug) {
                        echo "<pre>Debug: Parsed router line. Nickname: {$relay['Nickname']}, IPv4: {$relay['IPv4']}, ORPort: {$relay['ORPort']}, SOCKSPort: {$relay['SOCKSPort']}, DirPort: {$relay['DirPort']}</pre>";
                    }
                } else {
                    if ($debug) { echo "<pre>Debug: Incomplete router line: $line</pre>"; }
                }
                break;
            case 'uptime':
                if (count($tokens) >= 2) {
                    $relay['Uptime'] = $tokens[1];
                    if ($debug) { echo "<pre>Debug: Parsed uptime (seconds): " . $relay['Uptime'] . "</pre>"; }
                }
                break;
            case 'bandwidth':
                if (count($tokens) >= 4) {
                    $relay['Bandwidth_Avg'] = $tokens[1];
                    $relay['Bandwidth_Burst'] = $tokens[2];
                    $relay['Bandwidth_Observed'] = $tokens[3];
                    if ($debug) {
                        echo "<pre>Debug: Parsed bandwidth values (bytes/s): Sustained=" . $relay['Bandwidth_Avg'] . " Burst=" . $relay['Bandwidth_Burst'] . " Observed=" . $relay['Bandwidth_Observed'] . "</pre>";
                    }
                }
                break;
            case 'family':
                if (count($tokens) >= 2) {
                    $relay['Family'] = trim(implode(" ", array_slice($tokens, 1)));
                    if ($debug) { echo "<pre>Debug: Parsed family field: " . $relay['Family'] . "</pre>"; }
                }
                break;
            case 'contact':
                // Capture all tokens after 'contact' as the contact information.
                $contactInfo = trim(implode(" ", array_slice($tokens, 1)));
                if (isset($relay['Contact'])) {
                    $relay['Contact'] .= "; " . $contactInfo;
                } else {
                    $relay['Contact'] = $contactInfo;
                }
                if ($debug) {
                    echo "<pre>Debug: Parsed contact info: " . $contactInfo . "</pre>";
                }
                break;
            case 'fingerprint':
                if (count($tokens) >= 2) {
                    $relay['Fingerprint'] = implode(" ", array_slice($tokens, 1));
                    if ($debug) { echo "<pre>Debug: Parsed fingerprint: " . $relay['Fingerprint'] . "</pre>"; }
                }
                break;
            default:
                if ($debug) { echo "<pre>Debug: Unhandled keyword: $keyword - line: $line</pre>"; }
                break;
        }
    }
    return $relay;
}

/**
 * Parses a relay descriptor file and returns an array of relay arrays.
 *
 * @param string $file The file path.
 * @return array Array of relays.
 */
function parseRelayFile($file) {
    global $debug;
    $contents = file_get_contents($file);
    $relays = [];
    $blocks = preg_split('/(?=@type server-descriptor)/', $contents);
    if ($debug) {
        echo "<pre>Debug: Found " . count($blocks) . " blocks in file: $file</pre>";
    }
    foreach ($blocks as $block) {
        $block = trim($block);
        if (empty($block)) continue;
        $relay = parseRelayBlock($block);
        if (!empty($relay) && isset($relay['Nickname'])) {
            $relays[] = $relay;
            if ($debug) {
                echo "<pre>Debug: Added relay record for " . $relay['Nickname'] . "</pre>";
            }
        }
    }
    return $relays;
}

/**
 * Groups an array of relays by their family fingerprint.
 *
 * @param array $relays Array of relays.
 * @return array Relay groups keyed by family.
 */
function groupRelaysByFamily($relays) {
    global $debug;
    $familyGroups = [];
    foreach ($relays as $relay) {
        $groupKey = 'No Family';
        if (isset($relay['Family']) && !empty($relay['Family'])) {
            preg_match_all('/\$[A-Za-z0-9]{40}/', $relay['Family'], $matches);
            if (!empty($matches[0])) {
                $familyFingerprints = $matches[0];
                sort($familyFingerprints);
                $groupKey = implode(',', $familyFingerprints);
            }
        }
        if (!isset($familyGroups[$groupKey])) {
            $familyGroups[$groupKey] = [];
        }
        $uniqueKey = isset($relay['Fingerprint']) ? $relay['Fingerprint'] : $relay['Nickname'];
        $familyGroups[$groupKey][$uniqueKey] = $relay;
        if ($debug) {
            echo "<pre>Debug: Grouping relay '{$relay['Nickname']}' under family key: $groupKey</pre>";
        }
    }
    return $familyGroups;
}

/**
 * Prepares summary metrics for each relay family group.
 *
 * @param array $familyGroups Relay groups keyed by family.
 * @return array Summary metrics for each family.
 */
function prepareSummaryMetrics($familyGroups) {
    global $debug;
    $summary = [];
    foreach ($familyGroups as $familyKey => $relayGroup) {
        $numRelays = count($relayGroup);
        $uptimes = [];
        $bandwidths_avg = [];
        $bandwidths_burst = [];
        $bandwidths_observed = [];
        $ipv4s = [];
        $orports = [];
        $exitCount = 0;
        $contacts = [];
        
        foreach ($relayGroup as $relay) {
            if (isset($relay['Uptime'])) {
                $uptimes[] = floatval($relay['Uptime']);
            }
            if (isset($relay['Bandwidth_Avg'])) {
                $bandwidths_avg[] = floatval($relay['Bandwidth_Avg']);
            }
            if (isset($relay['Bandwidth_Burst'])) {
                $bandwidths_burst[] = floatval($relay['Bandwidth_Burst']);
            }
            if (isset($relay['Bandwidth_Observed'])) {
                $bandwidths_observed[] = floatval($relay['Bandwidth_Observed']);
            }
            if (isset($relay['IPv4'])) {
                $ipv4s[] = $relay['IPv4'];
            }
            if (isset($relay['ORPort'])) {
                $orports[] = $relay['ORPort'];
            }
            if (isset($relay['ExitRelay']) && $relay['ExitRelay'] === true) {
                $exitCount++;
            }
            if (isset($relay['Contact'])) {
                $contacts[] = $relay['Contact'];
            }
        }
        
        $nonExitCount = $numRelays - $exitCount;
        $avgUptimeSeconds = count($uptimes) > 0 ? array_sum($uptimes) / count($uptimes) : 0;
        $avgUptimeDays = $avgUptimeSeconds / 86400;
        $avgBandwidth_Avg = count($bandwidths_avg) > 0 ? array_sum($bandwidths_avg) / count($bandwidths_avg) : 0;
        $avgBandwidth_Burst = count($bandwidths_burst) > 0 ? array_sum($bandwidths_burst) / count($bandwidths_burst) : 0;
        $avgBandwidth_Observed = count($bandwidths_observed) > 0 ? array_sum($bandwidths_observed) / count($bandwidths_observed) : 0;
        $totalBandwidth_Avg = array_sum($bandwidths_avg);
        $totalBandwidth_Burst = array_sum($bandwidths_burst);
        $totalBandwidth_Observed = array_sum($bandwidths_observed);
        $conversionFactor = 1 / 1048576; // 1 MiB = 1048576 bytes
        $avgBandwidth_Avg_MiB = $avgBandwidth_Avg * $conversionFactor;
        $avgBandwidth_Burst_MiB = $avgBandwidth_Burst * $conversionFactor;
        $avgBandwidth_Observed_MiB = $avgBandwidth_Observed * $conversionFactor;
        $totalBandwidth_Avg_MiB = $totalBandwidth_Avg * $conversionFactor;
        $totalBandwidth_Burst_MiB = $totalBandwidth_Burst * $conversionFactor;
        $totalBandwidth_Observed_MiB = $totalBandwidth_Observed * $conversionFactor;
        $uniqueIPv4 = count(array_unique($ipv4s));
        $uniqueORPorts = count(array_unique($orports));
        
        // Look up unique AS for each unique IPv4.
        $uniqueAS = [];
        $ipv4NoASN = [];
        foreach (array_unique($ipv4s) as $ip) {
            $as = getASFromIP($ip);
            if (hasValidAS($as)) {
                $uniqueAS[$as] = true;
            } else {
                $ipv4NoASN[] = $ip;
            }
        }
        $uniqueASNCount = count($uniqueAS);
        $ipv4NoASNCount = count(array_unique($ipv4NoASN));
        
        // Combine unique contact info.
        $contacts = array_unique($contacts);
        $contactSummary = implode("; ", $contacts);
        
        $summary[$familyKey] = [
            'Contact' => $contactSummary,
            '# of Relays' => $numRelays,
            'Exit Count' => $exitCount,
            'Non-Exit Count' => $nonExitCount,
            'Avg Uptime (days)' => round($avgUptimeDays, 2),
            'Total Bandwidth Observed (MiB/s)' => round($totalBandwidth_Observed_MiB, 2),
            'Avg Bandwidth Observed (MiB/s)' => round($avgBandwidth_Observed_MiB, 2),
            'Unique IPv4 Addresses' => $uniqueIPv4,
            'Unique ORPorts' => $uniqueORPorts,
            'Unique ASN Count' => $uniqueASNCount,
            'IPv4 w/o ASN Count' => $ipv4NoASNCount,
            'Total Bandwidth Sustained (MiB/s)' => round($totalBandwidth_Avg_MiB, 2),
            'Avg Bandwidth Sustained (MiB/s)' => round($avgBandwidth_Avg_MiB, 2),
            'Avg Bandwidth Burst (MiB/s)' => round($avgBandwidth_Burst_MiB, 2),
            'Total Bandwidth Burst (MiB/s)' => round($totalBandwidth_Burst_MiB, 2)
        ];
    }
    return $summary;
}

/**
 * Outputs a table cell's content. If the content length is greater than 30 characters,
 * it collapses it within a <details> element.
 *
 * @param mixed $content The cell content.
 * @return string The HTML for the table cell content.
 */
function outputCell($content) {
    $str = (string)$content;
    $escaped = htmlspecialchars($str);
    if (strlen($str) > 30) {
        $short = substr($escaped, 0, 30) . '...';
        return "<details><summary>$short</summary><div style='white-space: pre-wrap;'>$escaped</div></details>";
    }
    return $escaped;
}

/**
 * Outputs the summary table as HTML with collapsible cell content and sortable columns.
 * Only columns starting from index 2 are sortable; "Family" and "Contact" are not.
 *
 * @param array $summary The summary metrics array.
 * @param string $headerTimestamp The latest timestamp from the input files.
 */
function outputSummaryTable($summary, $headerTimestamp) {
    // Add basic styling for details element within table cells.
    echo "<style>
            table td details { margin: 0; }
            table td details summary { cursor: pointer; }
          </style>";
    
    echo "<h2>Summary as of $headerTimestamp from Tor server descriptor files</h2>";
    echo "<table id='summaryTable' border='1' cellpadding='5' cellspacing='0'>";
    echo "<tr>
        <th>Family (Fingerprints)</th>
        <th>Contact</th>
        <th onclick='sortTable(this, 2)'># of Relays</th>
        <th onclick='sortTable(this, 3)'>Exit Count</th>
        <th onclick='sortTable(this, 4)'>Non-Exit Count</th>
        <th onclick='sortTable(this, 5)'>Avg Uptime (days)</th>
        <th onclick='sortTable(this, 6)'>Total Bandwidth Observed (MiB/s)</th>
        <th onclick='sortTable(this, 7)'>Avg Bandwidth Observed (MiB/s)</th>
        <th onclick='sortTable(this, 8)'>Unique IPv4 Addresses</th>
        <th onclick='sortTable(this, 9)'>Unique ORPorts</th>
        <th onclick='sortTable(this, 10)'>Unique ASN Count</th>
        <th onclick='sortTable(this, 11)'>IPv4 w/o ASN Count</th>
        <th onclick='sortTable(this, 12)'>Total Bandwidth Sustained (MiB/s)</th>
        <th onclick='sortTable(this, 13)'>Avg Bandwidth Sustained (MiB/s)</th>
        <th onclick='sortTable(this, 14)'>Avg Bandwidth Burst (MiB/s)</th>
        <th onclick='sortTable(this, 15)'>Total Bandwidth Burst (MiB/s)</th>
    </tr>";
    
    foreach ($summary as $familyKey => $data) {
        echo "<tr>";
        echo "<td>" . outputCell($familyKey) . "</td>";
        echo "<td>" . outputCell($data['Contact']) . "</td>";
        echo "<td>" . outputCell($data['# of Relays']) . "</td>";
        echo "<td>" . outputCell($data['Exit Count']) . "</td>";
        echo "<td>" . outputCell($data['Non-Exit Count']) . "</td>";
        echo "<td>" . outputCell($data['Avg Uptime (days)']) . "</td>";
        echo "<td>" . outputCell($data['Total Bandwidth Observed (MiB/s)']) . "</td>";
        echo "<td>" . outputCell($data['Avg Bandwidth Observed (MiB/s)']) . "</td>";
        echo "<td>" . outputCell($data['Unique IPv4 Addresses']) . "</td>";
        echo "<td>" . outputCell($data['Unique ORPorts']) . "</td>";
        echo "<td>" . outputCell($data['Unique ASN Count']) . "</td>";
        echo "<td>" . outputCell($data['IPv4 w/o ASN Count']) . "</td>";
        echo "<td>" . outputCell($data['Total Bandwidth Sustained (MiB/s)']) . "</td>";
        echo "<td>" . outputCell($data['Avg Bandwidth Sustained (MiB/s)']) . "</td>";
        echo "<td>" . outputCell($data['Avg Bandwidth Burst (MiB/s)']) . "</td>";
        echo "<td>" . outputCell($data['Total Bandwidth Burst (MiB/s)']) . "</td>";
        echo "</tr>";
    }
    echo "</table>";
    
    // Improved JavaScript sorting algorithm.
    echo "<script>
    function sortTable(th, n) {
      var table = document.getElementById('summaryTable');
      var tbody = table.tBodies[0] || table;
      var rows = Array.from(tbody.rows).slice(1);
      // Toggle sort direction on this header
      var dir = th.dataset.sortDir === 'asc' ? 'desc' : 'asc';
      th.dataset.sortDir = dir;
      // Reset sort direction for other headers
      var headers = table.getElementsByTagName('th');
      for (var i = 0; i < headers.length; i++) {
        if (headers[i] !== th) {
          headers[i].dataset.sortDir = '';
        }
      }
      // Precompute sort keys for each row.
      var rowData = rows.map(function(row) {
        var cell = row.cells[n];
        var detailsElem = cell.querySelector('details');
        var text = detailsElem ? detailsElem.querySelector('summary').textContent.trim() : cell.textContent.trim();
        var numericValue = parseFloat(text.replace(/[^0-9.-]+/g, ''));
        var key = (!isNaN(numericValue)) ? numericValue : text.toLowerCase();
        return { row: row, key: key };
      });
      rowData.sort(function(a, b) {
        if (a.key < b.key) return dir === 'asc' ? -1 : 1;
        if (a.key > b.key) return dir === 'asc' ? 1 : -1;
        return 0;
      });
      rowData.forEach(function(item) {
        tbody.appendChild(item.row);
      });
    }
    </script>";
}

// Main Execution:
date_default_timezone_set('UTC');
$dir = __DIR__;
$files = glob($dir . '/*-server-descriptors');
// Get latest timestamp from filenames.
$latestTimestamp = getLatestFileTimestamp($files);
$allRelays = [];
foreach ($files as $file) {
    $allRelays = array_merge($allRelays, parseRelayFile($file));
}
if ($debug) {
    echo "<pre>Debug: Total relays parsed from all files: " . count($allRelays) . "</pre>";
}
// Output overall parsing stats.
outputOverallParsingStats($allRelays);
$familyGroups = groupRelaysByFamily($allRelays);
$summary = prepareSummaryMetrics($familyGroups);
uasort($summary, function($a, $b) {
    return $b['# of Relays'] <=> $a['# of Relays'];
});
outputSummaryTable($summary, $latestTimestamp);
?>

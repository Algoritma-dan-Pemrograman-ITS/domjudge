<?php
/**
 * View the languages
 *
 * $Id$
 */

require('init.php');
$title = 'Languages';
require('../header.php');

echo "<h1>Languages</h1>\n\n";

$res = $DB->q('SELECT * FROM language ORDER BY name');

echo "<table>
<tr><th>ID</th><th>name</th><th>extension</th><th>allow<br>judge</th><th>timefactor</th></tr>\n";
while($row = $res->next()) {
	echo "<tr".
		( $row['allow_judge'] ? '': ' class="disabled"').
		"><td><a href=\"language.php?id=".urlencode($row['langid'])."\">".
			htmlspecialchars($row['langid'])."</a>".
		"</td><td>".htmlentities($row['name']).
		"</td><td class=\"filename\">.".htmlspecialchars($row['extension']).
		"</td><td align=\"center\">".printyn($row['allow_judge']).
		"</td><td>".(int)$row['time_factor'].
		"</td></tr>\n";
}
echo "</table>\n\n";
require('../footer.php');

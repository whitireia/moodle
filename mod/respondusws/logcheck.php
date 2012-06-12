<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
$moodlecfg_file = dirname(dirname(dirname(__FILE__))) . "/config.php";
if (is_readable($moodlecfg_file))
{
	require_once($moodlecfg_file);
}
else
{
	echo "Moodle configuration script file could not be found $moodlecfg_file";
	exit;
}
global $CFG;
if (isset($CFG->tempdir))
	$path = "$CFG->tempdir";
else
	$path = "$CFG->dataroot/temp";
$handle = fopen("$path/rwserr.log", "ab");
if ($handle === FALSE) {
	echo "Can't open error log $path/rwserr.log";
	exit;
}
$entry = date("m-d-Y H:i:s") . " - error log check\r\n";
fwrite($handle, $entry);
fclose($handle);
echo "Error log check okay.\r\n";
echo "Path is $path/rwserr.log";
exit;
// there is no php closing tag in this file;
// this is intentional because it prevents trailing whitespace problems

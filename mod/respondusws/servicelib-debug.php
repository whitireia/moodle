<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
$RWS_IGNORE_HTTPS_LOGIN = FALSE;
$RWS_ENABLE_CAS_AUTH = FALSE;
$RWS_ENABLE_CAS_SSL3 = FALSE; 
$RWS_SELF_RED_URL = "";
$RWS_CAS_RED_URL = "";
$RWS_PCFF_FIELD_NAME = "partiallycorrectfeedbackformat";
define("NO_DEBUG_DISPLAY", true);
$moodlecfg_file = dirname(dirname(dirname(__FILE__))) . "/config.php";
if (is_readable($moodlecfg_file))
    require_once($moodlecfg_file);
else  
	RWSServiceError("2002");
defined("MOODLE_INTERNAL") || die();
$script_found = TRUE;
if ($script_found)
	$script_found = is_readable("$CFG->dirroot/version.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/moodlelib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/datalib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/filelib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/completionlib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/conditionlib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/eventslib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/weblib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/accesslib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/dmllib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/ddllib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/questionlib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/grouplib.php");
if ($script_found)
	$script_found = is_readable("$CFG->libdir/gradelib.php");
if ($script_found)
	$script_found = is_readable("$CFG->dirroot/mod/quiz/lib.php");
if ($script_found)
	$script_found = is_readable("$CFG->dirroot/course/lib.php");
if ($script_found)
	$script_found = is_readable("$CFG->dirroot/mod/quiz/editlib.php");
if ($script_found)
	$script_found = is_readable("$CFG->dirroot/question/editlib.php");
if ($script_found && $RWS_ENABLE_CAS_AUTH)
	$script_found = is_readable("$CFG->dirroot/auth/cas/CAS/CAS.php");
if (!$script_found) {
	RWSServiceError("2003");
}
require_once("$CFG->dirroot/version.php");
require_once("$CFG->libdir/moodlelib.php");
require_once("$CFG->libdir/datalib.php");
require_once("$CFG->libdir/filelib.php");
require_once("$CFG->libdir/completionlib.php");
require_once("$CFG->libdir/conditionlib.php");
require_once("$CFG->libdir/eventslib.php");
require_once("$CFG->libdir/weblib.php");
require_once("$CFG->libdir/accesslib.php");
require_once("$CFG->libdir/dmllib.php");
require_once("$CFG->libdir/ddllib.php");
require_once("$CFG->libdir/questionlib.php");
require_once("$CFG->libdir/grouplib.php");
require_once("$CFG->libdir/gradelib.php");
require_once("$CFG->dirroot/mod/quiz/lib.php");
require_once("$CFG->dirroot/course/lib.php");
require_once("$CFG->dirroot/mod/quiz/editlib.php");
require_once("$CFG->dirroot/question/editlib.php");
if ($RWS_ENABLE_CAS_AUTH)
	require_once("$CFG->dirroot/auth/cas/CAS/CAS.php");
$RWS_LDB_INFO = new stdClass();
$RWS_LDB_INFO->attempts = 0; 
$RWS_LDB_INFO->reviews = 0; 
$RWS_LDB_INFO->password = ""; 
$RWS_LDB_INFO->module_ok = FALSE; 
$RWS_LDB_INFO->block_ok = FALSE; 
$RWS_LDB_INFO->get_settings_err = FALSE; 
$RWS_LDB_INFO->put_settings_err = FALSE; 
$RWS_LDB_INFO->module_exists = 
  is_readable("$CFG->dirroot/mod/lockdown/locklib.php");
$RWS_LDB_INFO->block_exists = 
  is_readable("$CFG->dirroot/blocks/lockdownbrowser/locklib.php");
if ($RWS_LDB_INFO->module_exists) {
	include_once("$CFG->dirroot/mod/lockdown/locklib.php");
	$RWS_LDB_INFO->module_ok = lockdown_module_status();
} else if ($RWS_LDB_INFO->block_exists) {
	include_once("$CFG->dirroot/blocks/lockdownbrowser/locklib.php");
	$RWS_LDB_INFO->block_ok = (!empty($CFG->customscripts)
	  && is_readable("$CFG->customscripts/mod/quiz/attempt.php")
	  && $DB->get_manager()->table_exists("block_lockdownbrowser_tokens")
	  && $DB->count_records("block_lockdownbrowser_tokens") > 0);
}
define("RWS_QUESTION_ADAPTIVE", 1);
define("RWS_QUIZ_REVIEW_RESPONSES", 1*0x1041);
define("RWS_QUIZ_REVIEW_SCORES", 2*0x1041);
define("RWS_QUIZ_REVIEW_FEEDBACK", 4*0x1041);
define("RWS_QUIZ_REVIEW_ANSWERS", 8*0x1041);
define("RWS_QUIZ_REVIEW_SOLUTIONS", 16*0x1041);
define("RWS_QUIZ_REVIEW_GENERALFEEDBACK", 32*0x1041);
define("RWS_QUIZ_REVIEW_OVERALLFEEDBACK", 1*0x4440000);
define("RWS_QUIZ_REVIEW_IMMEDIATELY", 0x3c003f);
define("RWS_QUIZ_REVIEW_OPEN", 0x3c00fc0);
define("RWS_QUIZ_REVIEW_CLOSED", 0x3c03f000);
define("RWS_QUIZ_REVIEW_DURING", 0x10000);
define("RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER", 0x01000);
define("RWS_QUIZ_REVIEW_LATER_WHILE_OPEN", 0x00100);
define("RWS_QUIZ_REVIEW_AFTER_CLOSE", 0x00010);
define("RWS_UNIT_INPUT", 0);
define("RWS_UNIT_NONE", 3);
define("RWS_UNIT_OPTIONAL", 0);
define("RWS_UNIT_GRADED", 1);
define("RWS_ATTACHMENT", "attachment");
define("RWS_RESERVED", "reserved");
define("RWS_UNKNOWN", "unknown");
define("RWS_SHORTANSWER", "shortanswer");
define("RWS_TRUEFALSE", "truefalse");
define("RWS_MULTIANSWER", "multianswer");
define("RWS_NUMERICAL", "numerical");
define("RWS_MULTICHOICE", "multichoice");
define("RWS_CALCULATED", "calculated");
define("RWS_MATCH", "match");
define("RWS_DESCRIPTION", "description");
define("RWS_ESSAY", "essay");
define("RWS_RANDOM", "random");
define("RWS_RANDOMSAMATCH", "randomsamatch");
define("RWS_CALCULATEDSIMPLE", "calculatedsimple");
define("RWS_CALCULATEDMULTI", "calculatedmulti");
define("RWS_AUTH_CAS", "cas");
define("RWS_REGEXP", "regexp");
function RWSResponseHeadersCommon()
{
	header("Cache-Control: private, must-revalidate"); 
	header("Expires: -1");
	header("Pragma: no-cache");
}
function RWSResponseHeadersXml()
{
	RWSResponseHeadersCommon();
	header("Content-Type: text/xml");
}
function RWSResponseHeadersBinary($file_name, $content_len)
{
	RWSResponseHeadersCommon();
	header("Content-Type: application/octet-stream");
	header("Content-Length: " . $content_len);
	header(
	  "Content-Disposition: attachment; filename=\""
	  . htmlspecialchars(trim($file_name)) . "\""
	  );
	header("Content-Transfer-Encoding: binary");
}
function RWSServiceWarning($warning_msg="")
{
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_warning>";
	if (!empty($warning_msg)) {
		RWSErrorLog("warning=$warning_msg");
		echo utf8_encode(htmlspecialchars($warning_msg));
	}
	else {
		RWSErrorLog("warning=3004");
		echo "3004"; 
	}
	echo "</service_warning>\r\n";
	exit;
}
function RWSServiceStatus($status_msg="")
{
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_status>";
	if (!empty($status_msg)) {
		RWSErrorLog("status=$status_msg");
		echo utf8_encode(htmlspecialchars($status_msg));
	}
	else {
		RWSErrorLog("status=1007");
		echo "1007"; 
	}
	echo "</service_status>\r\n";
	exit;
}
function RWSServiceError($error_msg="")
{
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_error>";
	if (!empty($error_msg)) {
		RWSErrorLog("error=$error_msg");
		echo utf8_encode(htmlspecialchars($error_msg));
	}
	else {
		RWSErrorLog("error=2004");
		echo "2004"; 
	}
	echo "</service_error>\r\n";
	exit;
}
function RWSLogoutMoodleUser()
{
    global $USER;
	global $CFG;
	global $RWS_ENABLE_CAS_AUTH;
	if (!$RWS_ENABLE_CAS_AUTH) {
		require_logout();
		RWSServiceStatus("1001"); 
	}
	if (RWSFloatCompare($CFG->version, 2010122500, 2) >= 0) {
		$params = $USER;
		if (isloggedin()) {
			$auth_sequence = get_enabled_auth_plugins();
			foreach ($auth_sequence as $auth_name) {
				$auth_plugin = get_auth_plugin($auth_name);
				if (strcasecmp($auth_plugin->authtype, RWS_AUTH_CAS) == 0) {
					$cas_plugin = $auth_plugin;
					RWSPrelogoutCAS($cas_plugin);
				} else {
					$auth_plugin->prelogout_hook();
				}
			}
		}
		events_trigger('user_logout', $params);
		session_get_instance()->terminate_current();
		unset($params);
	} else {
		RWSServiceError("2006,$CFG->version,2010122500");
	}
	RWSServiceStatus("1001"); 
}
function RWSCheckModuleBehaviorVersion()
{
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0) {
		return;
	}
	$behavior_version = intval($requested_version);
	if ($behavior_version == 2009093000		
	  || $behavior_version == 2010042801	
	  || $behavior_version == 2010063001	
	  || $behavior_version == 2010063002	
	  || $behavior_version == 2010063003	
	  || $behavior_version == 2010063004	
	  || $behavior_version == 2010063005	
	  || $behavior_version == 2011020100	
	  || $behavior_version == 2011040400	
	  || $behavior_version == 2011071500	
	  || $behavior_version == 2011080100	
	  || $behavior_version == 2011102500	
	  || $behavior_version == 2011121500	
	  ) {
		return; 
	}
	RWSServiceError("2106");
}
function RWSCheckMoodleVersion()
{
	global $CFG;
	$requires = "";
	$version_file = RWSGetModulePath() . "/version.php";
	if (is_readable($version_file))
		include($version_file);
	if ($module) {
		if (!empty($module->requires))
			$requires = $module->requires;
	}
	if (empty($requires)) {
		RWSServiceError("2005");
	}
	$result = RWSFloatCompare($CFG->version, $requires, 2);
	if ($result == -1) {
		RWSServiceError("2006,$CFG->version,$requires");
	}
	else if ($result == 1) {
	}
}
function RWSCheckModuleInstalled()
{
	global $DB;
	$dbman = $DB->get_manager();
	if ($dbman->table_exists("respondusws"))
		$instances = $DB->get_records("respondusws", array("course" => SITEID));
	else
		$instances = array();
	$ok = (count($instances) == 1);
	if (!$ok) {
		RWSServiceError("2007");
	}
}
function RWSAddToLog($course_id, $action, $info="")
{
	add_to_log($course_id, "respondusws", $action,
	 "index.php?id=$course_id", $info);
}
function RWSGetModulePath()
{
	$module_path = dirname(__FILE__); 
	if (DIRECTORY_SEPARATOR != '/') 
	  $module_path = str_replace('\\', '/', $module_path);
	return $module_path;
}
function RWSGetTempPath()
{
	global $CFG;
	if (RWSFloatCompare($CFG->version, 2011120500.00, 2) >= 0) { 
		if (isset($CFG->tempdir))
			$temp_path = "$CFG->tempdir";
		else
			$temp_path = "$CFG->dataroot/temp";
	}
	else { 
		$temp_path = "$CFG->dataroot/temp";
	}
	return $temp_path;
}
function RWSGetSelfURL($force_https, $include_query)
{
	$https = $force_https;
	if (!$https) {
		$https = (isset($_SERVER['HTTPS'])
		  && !empty($_SERVER['HTTPS'])
		  && strcasecmp($_SERVER['HTTPS'], "off") != 0);
	}
	if ($https)
		$self_url = 'https://';
	else
		$self_url = 'http://';
	if (empty($_SERVER['HTTP_X_FORWARDED_SERVER'])) {
		if (empty($_SERVER['SERVER_NAME'])) {
			$self_url .= $_SERVER['HTTP_HOST'];
		} else {
			$self_url .= $_SERVER['SERVER_NAME'];
		}
	} else {
		$self_url .= $_SERVER['HTTP_X_FORWARDED_SERVER'];
	}
	if (strpos($self_url, ":") === FALSE) {
		if (($https && $_SERVER['SERVER_PORT'] != 443)
		  || (!$https && $_SERVER['SERVER_PORT'] != 80)) {
			$self_url .= ':';
			$self_url .= $_SERVER['SERVER_PORT'];
		}
	}
	if (!isset($_SERVER['REQUEST_URI'])) {
		$_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'];
		if (isset($_SERVER['QUERY_STRING'])) {
			$_SERVER['REQUEST_URI'] .= '?';
			$_SERVER['REQUEST_URI'] .= $_SERVER['QUERY_STRING'];
		}
	}
	$base_url = explode("?", $_SERVER['REQUEST_URI'], 2);
	$self_url .= $base_url[0];
	if ($include_query) {
		$query = "";
		if ($_GET) {
			$parms = array();
			foreach ($_GET as $key => $value)
				$parms[] = urlencode($key) . "=" . urlencode($value);
			$query = join("&", $parms);
		}
		if (strlen($query) > 0)
			$self_url .= "?" . $query;
	}
	return $self_url;
}
function RWSAuthenticateMoodleUser($username, $password, $cas_failed)
{
	global $RWS_ENABLE_CAS_AUTH;
	if ($RWS_ENABLE_CAS_AUTH)
		RWSPreloginCAS($username, $password, $cas_failed);
	$user = authenticate_user_login($username, $password);
	if ($user)
		complete_user_login($user);
	if (isloggedin()) {
		RWSServiceStatus("1000"); 
	} else {
		if ($RWS_ENABLE_CAS_AUTH) {
			if (isset($_SESSION['rwscas']['cookiejar'])) {
				$cookie_file = $_SESSION['rwscas']['cookiejar'];
				if (file_exists($cookie_file))
					unlink($cookie_file);
				unset($_SESSION['rwscas']['cookiejar']); 
			}
			unset($_SESSION['rwscas']);
		}
		RWSServiceError("2008"); 
	}
}
function RWSPreloginCAS($username, $password, $cas_failed)
{
	global $RWS_ENABLE_CAS_SSL3;
	global $RWS_SELF_RED_URL;
	global $RWS_CAS_RED_URL;
	if ($cas_failed)
		return;
	$auth_sequence = get_enabled_auth_plugins();
    foreach ($auth_sequence as $auth_name) {
		$auth_plugin = get_auth_plugin($auth_name);
		if (strcasecmp($auth_plugin->authtype, RWS_AUTH_CAS) == 0) {
			$cas_plugin = $auth_plugin;
			break;
		}
	}
	if (!isset($cas_plugin))
		return;
	if (empty($cas_plugin->config->hostname))
		return;
	if ($cas_plugin->config->multiauth) {
		$auth_cas = RWSGetServiceOption("authCAS");
		if ($auth_cas === FALSE || strlen($auth_cas) == 0)
			$auth_cas = "CAS";
		if (strcasecmp($auth_cas, "CAS") != 0)
			return;
	}
	list($v1, $v2, $v3) = explode(".", phpCAS::getVersion());
	$cas_plugin->connectCAS();
	if (phpCAS::isSessionAuthenticated())
		return;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		unset($behavior_version);
	else
		$behavior_version = intval($requested_version);
	if (strlen($RWS_CAS_RED_URL) > 0)
		$service_url = $RWS_CAS_RED_URL;
	else
		$service_url = RWSGetSelfURL(FALSE, FALSE);
	$service_url .= "?rwscas=1"; 
	if (isset($behavior_version)) {
		$service_url .= "&version=";
		$service_url .= urlencode($behavior_version);
	}
	if (isset($username)) {
		$service_url .= "&rwsuser=";
		$service_url .= urlencode($username);
	}
	if (isset($password)) {
		$service_url .= "&rwspass=";
		$service_url .= urlencode($password);
	}
	phpCAS::setFixedServiceURL($service_url);
	if ($cas_plugin->config->proxycas) {
		if (strlen($RWS_CAS_RED_URL) > 0)
			$callback_url = $RWS_CAS_RED_URL;
		else
			$callback_url = RWSGetSelfURL(TRUE, FALSE);
		$callback_url .= "?rwscas=2";  
		if (isset($behavior_version)) {
			$callback_url .= "&version=";
			$callback_url .= urlencode($behavior_version);
		}
		if (isset($username)) {
			$callback_url .= "&rwsuser=";
			$callback_url .= urlencode($username);
		}
		if (isset($password)) {
			$callback_url .= "&rwspass=";
			$callback_url .= urlencode($password);
		}
			phpCAS::setFixedCallbackURL($callback_url);
	}
	$tmppath = RWSGetTempPath();
	if ($tmppath !== FALSE) {
		$cookie_file = tempnam($tmppath, "rws");
		if ($cookie_file !== FALSE)
			$_SESSION['rwscas']['cookiejar'] = $cookie_file;
	}
	$login_url = phpCAS::getServerLoginURL();
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $login_url);
	curl_setopt($ch, CURLOPT_HTTPGET, TRUE);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($ch, CURLOPT_HEADER, TRUE);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($ch, CURLOPT_FAILONERROR, TRUE);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30); 
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
	if ($RWS_ENABLE_CAS_SSL3)
		curl_setopt($ch, CURLOPT_SSLVERSION, 3);
	curl_setopt($ch, CURLOPT_USERAGENT, "PHP");
	if (isset($cookie_file)) {
		curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file); 
		curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);  
	}
	$response = curl_exec($ch);
	if ($response === FALSE) {
		curl_close($ch);
		return;
	}
	$pos = 0;
	while (stripos($response, "HTTP/", $pos) === 0) {
		$pos = stripos($response, "\r\n\r\n", $pos);
		if ($pos === FALSE)
			break;
		$pos += 4;
	}
	if ($pos === 0) {
		$headers = "";
		$header_sets = "";
		$body = $response;
	} else if ($pos === FALSE) {
		$headers = $response;
		$header_sets = explode("\r\n\r\n", $headers);
		$body = "";
	} else {
		$headers = substr($response, 0, $pos - 4);
		$header_sets = explode("\r\n\r\n", $headers);
		$body = substr($response, $pos);
	}
	$action = "";
	$lt = "";
	$event_id = "";
	$submit = "";
	$pos = 0;
	$len = strlen($body);
	$start = stripos($body, "<form ");
	if ($start !== FALSE) {
		$end = stripos($body, ">", $start);
		if ($end === FALSE)
			$end = $len;
		$pos = stripos($body, "action=\"", $start);
		if ($pos === FALSE || $pos > $end)
			$pos = stripos($body, "action = \"", $start);
		if ($pos === FALSE || $pos > $end)
			$pos = stripos($body, "action=\'", $start);
		if ($pos === FALSE || $pos > $end)
			$pos = stripos($body, "action = \'", $start);
		if ($pos !== FALSE && $pos < $end) {
			while ($body[$pos] != "\"" && $body[$pos] != "\'")
				$pos++;
			$pos++;
			$start = $pos;
			while ($pos < $end && $body[$pos] != "\"" && $body[$pos] != "\'")
				$pos++;
			$end = $pos;
			$action = substr($body, $start, $end - $start);
		}
	}
	while (strlen($lt) == 0
	  || strlen($event_id) == 0
	  || strlen($submit) == 0) {
		$next = stripos($body, "<input ", $pos);
		if ($next === FALSE)
			break;
		$start = $next;
		$end = stripos($body, ">", $start);
		if ($end === FALSE)
			$end = $len;
		if (strlen($lt) == 0) {
			$start = stripos($body, "name=\"lt\"", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name = \"lt\"", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name=\'lt\'", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name = \'lt\'", $next);
			if ($start !== FALSE && $start < $end) {
				$pos = stripos($body, "value=\"", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value = \"", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value=\'", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value = \'", $start);
				if ($pos !== FALSE && $pos < $end) {
					while ($body[$pos] != "\"" && $body[$pos] != "\'")
						$pos++;
					$pos++;
					$start = $pos;
					while ($pos < $end && $body[$pos] != "\"" && $body[$pos] != "\'")
						$pos++;
					$end = $pos;
					$lt = substr($body, $start, $end - $start);
				}
			}
		}
		if (strlen($event_id) == 0) {
			$start = stripos($body, "name=\"_eventId\"", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name = \"_eventId\"", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name=\'_eventId\'", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name = \'_eventId\'", $next);
			if ($start !== FALSE && $start < $end) {
				$pos = stripos($body, "value=\"", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value = \"", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value=\'", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value = \'", $start);
				if ($pos !== FALSE && $pos < $end) {
					while ($body[$pos] != "\"" && $body[$pos] != "\'")
						$pos++;
					$pos++;
					$start = $pos;
					while ($pos < $end && $body[$pos] != "\"" && $body[$pos] != "\'")
						$pos++;
					$end = $pos;
					$event_id = substr($body, $start, $end - $start);
				}
			}
		}
		if (strlen($submit) == 0) {
			$start = stripos($body, "name=\"submit\"", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name = \"submit\"", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name=\'submit\'", $next);
			if ($start === FALSE || $start > $end)
				$start = stripos($body, "name = \'submit\'", $next);
			if ($start !== FALSE && $start < $end) {
				$pos = stripos($body, "value=\"", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value = \"", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value=\'", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = stripos($body, "value = \'", $start);
				if ($pos !== FALSE && $pos < $end) {
					while ($body[$pos] != "\"" && $body[$pos] != "\'")
						$pos++;
					$pos++;
					$start = $pos;
					while ($pos < $end && $body[$pos] != "\"" && $body[$pos] != "\'")
						$pos++;
					$end = $pos;
					$submit = substr($body, $start, $end - $start);
				}
			}
		}
		$pos = $next + 1;
	}
	if (strlen($action) == 0 || strlen($lt) == 0) {
		curl_close($ch);
		return;
	}
	if (strlen($event_id) == 0)
		unset($event_id);
	if (isset($event_id) && strlen($submit) == 0) {
		$submit = "LOGIN"; 
	}
	if (stripos($action, "http://") !== 0
	  && stripos($action, "https://") !== 0) {
		if ($action[0] == "/") {
			$pos = stripos($login_url, "://");
			if ($pos !== FALSE) {
				$pos += 3;
				$pos = stripos($login_url, "/", $pos);
				if ($pos !== FALSE) {
					$action_url = substr($login_url, 0, $pos);
					$action_url .= $action;
				}
			}
		} else {
			$pos = stripos($login_url, "/login?");
			if ($pos !== FALSE) {
				$action_url = substr($login_url, 0, $pos);
				$action_url .= "/$action";
			}
		}
	} else {
		$action_url = $action;
	}
	if (!isset($action_url))
		$action_url = $login_url;
	$post_fields = "username=";
	$post_fields .= urlencode($username);
	$post_fields .= "&password=";
	$post_fields .= urlencode($password);
	$post_fields .= "&lt=";
	$post_fields .= urlencode($lt);
	$post_fields .= "&service=";
	$post_fields .= urlencode($service_url);
	if (isset($event_id)) {
		$post_fields .= "&_eventId=";
		$post_fields .= urlencode($event_id);
		$post_fields .= "&submit=";
		$post_fields .= urlencode($submit);
	}
	curl_setopt($ch, CURLOPT_URL, $action_url);
	curl_setopt($ch, CURLOPT_HTTPGET, FALSE);
	curl_setopt($ch, CURLOPT_POST, TRUE);
	curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
	$response = curl_exec($ch);
	if ($response === FALSE) {
		curl_close($ch);
		return;
	}
	$pos = 0;
	while (stripos($response, "HTTP/", $pos) === 0) {
		$pos = stripos($response, "\r\n\r\n", $pos);
		if ($pos === FALSE)
			break;
		$pos += 4;
	}
	if ($pos === 0) {
		$headers = "";
		$header_sets = "";
		$body = $response;
	} else if ($pos === FALSE) {
		$headers = $response;
		$header_sets = explode("\r\n\r\n", $headers);
		$body = "";
	} else {
		$headers = substr($response, 0, $pos - 4);
		$header_sets = explode("\r\n\r\n", $headers);
		$body = substr($response, $pos);
	}
	foreach ($header_sets as $set) {
		$header_lines = explode("\r\n", $set);
		foreach ($header_lines as $header) {
			if (stripos($header, "Location:") !== FALSE) {
				$start = stripos($header, "?ticket=");
				if ($start === FALSE)
					$start = stripos($header, "&ticket=");
				if ($start !== FALSE) {
					$end = stripos($header, "&", $start + 1);
					if ($end === FALSE)
						$end = strlen($header);
					$param = substr($header, $start + 8, $end - $start);
					if ($param !== FALSE && strlen($param) > 0) {
						$ticket = trim(urldecode($param));
						break;
					}
				}
			}
		}
		if (isset($ticket))
			break;
	}
	$redir_url = "";
	$pos = 0;
	$len = strlen($body);
	while (strlen($redir_url) == 0) {
		$next = stripos($body, "window.location.href", $pos);
		if ($next === FALSE)
			$next = stripos($body, "window.location.replace", $pos);
		if ($next === FALSE)
			$next = stripos($body, "window.location", $pos);
		if ($next === FALSE)
			$next = stripos($body, "window.navigate", $pos);
		if ($next === FALSE)
			$next = stripos($body, "document.location.href", $pos);
		if ($next === FALSE)
			$next = stripos($body, "document.location.URL", $pos);
		if ($next === FALSE)
			$next = stripos($body, "document.location", $pos);
		if ($next === FALSE)
			break;
		$pos = $next;
		while ($pos < $len && $body[$pos] != "\"" && $body[$pos] != "\'")
			$pos++;
		if ($pos < $len)
			$pos++;
		$start = $pos;
		while ($pos < $end && $body[$pos] != "\"" && $body[$pos] != "\'")
			$pos++;
		$end = $pos;
		$redir_url = substr($body, $start, $end - $start);
		$start = stripos($redir_url, "?ticket=");
		if ($start === FALSE)
			$start = stripos($redir_url, "&ticket=");
		if ($start !== FALSE) {
			$end = stripos($redir_url, "&", $start + 1);
			if ($end === FALSE)
				$end = strlen($redir_url);
			$param = substr($redir_url, $start + 8, $end - $start);
			if ($param !== FALSE && strlen($param) > 0)
				$ticket = trim(urldecode($param));
		}
		if (!isset($ticket))
			$redir_url = "";
		$pos = $next + 1;
	}
	if (strlen($redir_url) != 0) {
		curl_setopt($ch, CURLOPT_URL, $redir_url);
		curl_setopt($ch, CURLOPT_HTTPGET, TRUE);
		curl_setopt($ch, CURLOPT_POST, FALSE);
		curl_setopt($ch, CURLOPT_POSTFIELDS, "");
		$redir_res = curl_exec($ch);
		if ($redir_res !== FALSE) {
			$response = $redir_res;
			$pos = 0;
			while (stripos($response, "HTTP/", $pos) === 0) {
				$pos = stripos($response, "\r\n\r\n", $pos);
				if ($pos === FALSE)
					break;
				$pos += 4;
			}
			if ($pos === 0) {
				$headers = "";
				$header_sets = "";
				$body = $response;
			} else if ($pos === FALSE) {
				$headers = $response;
				$header_sets = explode("\r\n\r\n", $headers);
				$body = "";
			} else {
				$headers = substr($response, 0, $pos - 4);
				$header_sets = explode("\r\n\r\n", $headers);
				$body = substr($response, $pos);
			}
		}
	}
	$autosub_url = "";
	$post_fields = "";
	if (strlen($redir_url) == 0) {
	}
	if (strlen($autosub_url) != 0) {
		curl_setopt($ch, CURLOPT_URL, $autosub_url);
		curl_setopt($ch, CURLOPT_HTTPGET, FALSE);
		curl_setopt($ch, CURLOPT_POST, TRUE);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
		$autosub_res = curl_exec($ch);
		if ($autosub_res !== FALSE) {
			$response = $autosub_res;
			$pos = 0;
			while (stripos($response, "HTTP/", $pos) === 0) {
				$pos = stripos($response, "\r\n\r\n", $pos);
				if ($pos === FALSE)
					break;
				$pos += 4;
			}
			if ($pos === 0) {
				$headers = "";
				$header_sets = "";
				$body = $response;
			} else if ($pos === FALSE) {
				$headers = $response;
				$header_sets = explode("\r\n\r\n", $headers);
				$body = "";
			} else {
				$headers = substr($response, 0, $pos - 4);
				$header_sets = explode("\r\n\r\n", $headers);
				$body = substr($response, $pos);
			}
		}
	}
	if (!isset($ticket)) {
		$start = stripos($body, "<rwscas>");
		if ($start !== FALSE) {
			$end = stripos($body, "</rwscas>", $start);
			if ($end === FALSE)
				$end = strlen($header);
			$pos = stripos($body, "<st>", $start);
			if ($pos !== FALSE && $pos < $end) {
				$pos += 4;
				$start = $pos;
				$pos = stripos($body, "</st>", $start);
				if ($pos === FALSE || $pos > $end)
					$pos = $end;
				$end = $pos;
				$param = trim(substr($body, $start, $end));
				if (strlen($param))
					$ticket = $param;
			}
		}
	}
	curl_close($ch);
	if (!isset($ticket))
		return;
	if (strlen($RWS_SELF_RED_URL) > 0)
		$redir_url = $RWS_SELF_RED_URL;
	else
		$redir_url = RWSGetSelfURL(FALSE, FALSE);
	$redir_url .= "?rwscas=3"; 
	if (isset($behavior_version)) {
		$redir_url .= "&version=";
		$redir_url .= urlencode($behavior_version);
	}
	if (isset($username)) {
		$redir_url .= "&rwsuser=";
		$redir_url .= urlencode($username);
	}
	if (isset($password)) {
		$redir_url .= "&rwspass=";
		$redir_url .= urlencode($password);
	}
	if (isset($ticket)) {
		$redir_url .= "&ticket=";
		$redir_url .= urlencode($ticket);
	}
	header("Location: $redir_url");
	exit;
}
function RWSProcessCASRequests()
{
	global $RWS_ENABLE_CAS_SSL3;
	global $RWS_CAS_RED_URL;
	$rwscas = RWSGetServiceOption("rwscas");
	if ($rwscas === FALSE || strlen($rwscas) == 0)
		return;
	if ($rwscas != "1" && $rwscas != "2" && $rwscas != "3")
		return;
	$version = RWSGetServiceOption("version");
	if ($version === FALSE || strlen($version) == 0)
		return;
	$rwsuser = RWSGetServiceOption("rwsuser");
	if ($rwsuser === FALSE || strlen($rwsuser) == 0)
		unset($rwsuser);
	$rwspass = RWSGetServiceOption("rwspass");
	if ($rwspass === FALSE || strlen($rwspass) == 0)
		unset($rwspass);
	$ticket = RWSGetServiceOption("ticket");
	if ($ticket === FALSE || strlen($ticket) == 0)
		unset($ticket);
	$pgt_id = RWSGetServiceOption("pgtId");
	if ($pgt_id === FALSE || strlen($pgt_id) == 0)
		unset($pgt_id);
	$pgt_iou = RWSGetServiceOption("pgtIou");
	if ($pgt_iou === FALSE || strlen($pgt_iou) == 0)
		unset($pgt_iou);
	$auth_sequence = get_enabled_auth_plugins();
	foreach ($auth_sequence as $auth_name) {
		$auth_plugin = get_auth_plugin($auth_name);
		if (strcasecmp($auth_plugin->authtype, RWS_AUTH_CAS) == 0) {
			$cas_plugin = $auth_plugin;
			break;
		}
	}
	if (!isset($cas_plugin))
		return;
	if (empty($cas_plugin->config->hostname))
		return;
	list($v1, $v2, $v3) = explode(".", phpCAS::getVersion());
	$cas_plugin->connectCAS();
	if ($rwscas == "1") { 
		if (isset($ticket)) {
			RWSResponseHeadersXml();
			echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
			echo "<rwscas>\r\n";
			echo "\t<st>";
			echo utf8_encode(htmlspecialchars(trim($ticket)));
			echo "\t</st>\r\n";
			echo "</rwscas>\r\n";
			exit;
		} else if ($_SERVER['REQUEST_METHOD'] == "GET") {
			$ok = phpCAS::checkAuthentication();
			if (!isset($rwsuser))
				$rwsuser = phpCAS::getUser();
			if (!isset($rwspass))
				$rwspass = "passwdCas"; 
			RWSAuthenticateMoodleUser($rwsuser, $rwspass, $ok);
		} else if ($_SERVER['REQUEST_METHOD'] == "POST") {
			$postdata = urldecode(file_get_contents("php://input"));
			if (stripos($postdata, "<samlp:LogoutRequest ") !== FALSE)
				RWSActionLogout();
		}
	} else if ($rwscas == "2") { 
		if (isset($pgt_id) && isset($pgt_iou)) {
			if ($cas_plugin->config->proxycas)
				phpCAS::checkAuthentication();
		} else if ($_SERVER['REQUEST_METHOD'] == "POST") {
			$postdata = urldecode(file_get_contents("php://input"));
			if (stripos($postdata, "<samlp:LogoutRequest ") !== FALSE)
				RWSActionLogout();
		}
	} else if ($rwscas == "3") { 
		if (isset($ticket)) {
			if (strlen($RWS_CAS_RED_URL) > 0)
				$service_url = $RWS_CAS_RED_URL;
			else
				$service_url = RWSGetSelfURL(FALSE, FALSE);
			$service_url .= "?rwscas=1"; 
			if (isset($version)) {
				$service_url .= "&version=";
				$service_url .= urlencode($version);
			}
			if (isset($rwsuser)) {
				$service_url .= "&rwsuser=";
				$service_url .= urlencode($rwsuser);
			}
			if (isset($rwspass)) {
				$service_url .= "&rwspass=";
				$service_url .= urlencode($rwspass);
			}
			phpCAS::setFixedServiceURL($service_url);
			if ($cas_plugin->config->proxycas) {
				if (strlen($RWS_CAS_RED_URL) > 0)
					$callback_url = $RWS_CAS_RED_URL;
				else
					$callback_url = RWSGetSelfURL(TRUE, FALSE);
				$callback_url .= "?rwscas=2"; 
				if (isset($version)) {
					$callback_url .= "&version=";
					$callback_url .= urlencode($version);
				}
				if (isset($rwsuser)) {
					$callback_url .= "&rwsuser=";
					$callback_url .= urlencode($rwsuser);
				}
				if (isset($rwspass)) {
					$callback_url .= "&rwspass=";
					$callback_url .= urlencode($rwspass);
				}
					phpCAS::setFixedCallbackURL($callback_url);
			}
			if (phpCAS::checkAuthentication())
				exit; 
			RWSAuthenticateMoodleUser($rwsuser, $rwspass, TRUE);
		}
	}
	RWSServiceError("2008"); 
}
function RWSCheckMoodleMaintenance()
{
	global $CFG;
	if (is_siteadmin())
		return;
	if (!empty($CFG->maintenance_enabled)
	  || file_exists($CFG->dataroot . "/" . SITEID . "/maintenance.html")) {
		RWSServiceError("2009");
	}
}
function RWSCheckMoodleAuthentication()
{
	if (!isloggedin()) {
		RWSServiceError("2010");
	}
}
function RWSCheckMoodleUserCourse($course_id, $check_quiz_allowed=FALSE)
{
	global $DB;
	$record = $DB->get_record("course", array("id" => $course_id));
	if ($record === FALSE) 
		RWSServiceError("2011");
	if ($check_quiz_allowed && !course_allowed_module($record, "quiz")) {
		RWSServiceError("2012");
	}
	if (!RWSIsMoodleUserModifyCourse($course_id)) {
		RWSServiceError("2013");
	}
	return $record; 
}
function RWSCheckMoodleUserQuiz($quiz_cmid)
{
	global $DB;
	$record = $DB->get_record("course_modules", array("id" => $quiz_cmid));
	if ($record === FALSE)
		RWSServiceError("2014"); 
	if (!RWSIsMoodleUserModifyQuiz($quiz_cmid)) {
		RWSServiceError("2015");
	}
	return $record; 
}
function RWSGetMoodleUserQCats($course_id)
{
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$context_ids = array();
	if ($behavior_version >= 2010063001) { 
		if (is_siteadmin()) {
			$sysctx = get_context_instance(CONTEXT_SYSTEM);
			$context_ids[] = $sysctx->id;
		}
	}
	$context = get_context_instance(CONTEXT_COURSE, $course_id);
	$context_ids[] = $context->id;
	$quiz_cms = RWSGetMoodleUserVisibleQuizzes($course_id);
	if (count($quiz_cms) > 0) {
		foreach ($quiz_cms as $qzm) {
			$context = get_context_instance(CONTEXT_MODULE, $qzm->id);
			if ($context != FALSE) {
				if (!in_array($context->id, $context_ids))
					$context_ids[] = $context->id;
			}
		}
	}
	if (count($context_ids) == 0) {
		return array();
	}
	else if (count($context_ids) == 1) {
		$qcats = get_categories_for_contexts($context_ids[0]);
		if ($qcats === FALSE || count($qcats) == 0)
			return array();
	}
	else {
		$context_list = implode(", ", $context_ids);
		$qcats = get_categories_for_contexts($context_list);
		if ($qcats === FALSE || count($qcats) == 0)
			return array();
	}
	return $qcats;
}
function RWSGetMoodleUserVisibleSections($course_id)
{
	$visible_sections = array();
	$sections = get_all_sections($course_id);
	if ($sections === FALSE || count($sections) == 0)
		return $visible_sections;
	$context = get_context_instance(CONTEXT_COURSE, $course_id);
	$view_hidden = has_capability("moodle/course:viewhiddensections", $context);
	if (!$view_hidden) 
		$view_hidden = is_siteadmin();
	foreach ($sections as $s) {
		if ($s->visible || $view_hidden)
			$visible_sections[] = $s;
	}
	return $sections;
}
function RWSGetMoodleUserVisibleQuizzes($course_id)
{
	$visible_quizcms = array();
	$quiz_cms = get_coursemodules_in_course("quiz", $course_id);
	if ($quiz_cms === FALSE || count($quiz_cms) == 0)
		return $visible_quizcms;
	foreach ($quiz_cms as $qzm) {
		if (coursemodule_visible_for_user($qzm))
			$visible_quizcms[] = $qzm;
    }
	return $visible_quizcms;
}
function RWSGetMoodleUserModifyQuizzes($quiz_cms)
{
	$modify_quizcms = array();
	if (!$quiz_cms || count($quiz_cms) == 0)
		return $modify_quizcms;
	foreach ($quiz_cms as $qzm) {
		if (RWSIsMoodleUserModifyQuiz($qzm->id))
			$modify_quizcms[] = $qzm;
    }
	return $modify_quizcms;
}
function RWSIsMoodleUserModifyQuiz($quiz_cmid)
{
	$context = get_context_instance(CONTEXT_MODULE, $quiz_cmid);
	$ok = ($context !== FALSE);
	if ($ok)
		$ok = has_capability("mod/quiz:view", $context);
	if ($ok)
		$ok = has_capability("mod/quiz:preview", $context);
	if ($ok)
		$ok = has_capability("mod/quiz:manage", $context);
	if (!$ok)
		$ok = is_siteadmin();
	return $ok;
}
function RWSGetMoodleUserModifyCourses()
{
	$modify_courses = array();
	$courses = get_courses();
	if ($courses === FALSE || count($courses) == 0)
		return $modify_courses;
    if (array_key_exists(SITEID, $courses))
        unset($courses[SITEID]);
	if (count($courses) == 0)
		return $modify_courses;
	foreach ($courses as $c) {
		if (RWSIsMoodleUserModifyCourse($c->id))
			$modify_courses[] = $c;
    }
	return $modify_courses;
}
function RWSCheckMoodleUserWebService()
{
}
function RWSIsMoodleUserModifyCourse($course_id)
{
	$context = get_context_instance(CONTEXT_COURSE, $course_id);
	$ok = ($context !== FALSE);
	if ($ok)
		$ok = has_capability("moodle/site:viewfullnames", $context);
	if ($ok)
		$ok = has_capability("moodle/course:activityvisibility", $context);
	if ($ok)
		$ok = has_capability("moodle/course:viewhiddencourses", $context);
	if ($ok)
		$ok = has_capability("moodle/course:viewhiddenactivities", $context);
	if ($ok)
		$ok = has_capability("moodle/course:viewhiddensections", $context);
	if ($ok)
		$ok = has_capability("moodle/course:update", $context);
	if ($ok)
		$ok = has_capability("moodle/course:manageactivities", $context);
	if ($ok)
		$ok = has_capability("moodle/course:managefiles", $context);
	if ($ok)
		$ok = has_capability("moodle/question:managecategory", $context);
	if ($ok)
		$ok = has_capability("moodle/question:add", $context);
	if ($ok)
		$ok = has_capability("moodle/question:editmine", $context);
	if ($ok)
		$ok = has_capability("moodle/question:editall", $context);
	if ($ok)
		$ok = has_capability("moodle/question:viewmine", $context);
	if ($ok)
		$ok = has_capability("moodle/question:viewall", $context);
	if ($ok)
		$ok = has_capability("moodle/question:usemine", $context);
	if ($ok)
		$ok = has_capability("moodle/question:useall", $context);
	if ($ok)
		$ok = has_capability("moodle/question:movemine", $context);
	if ($ok)
		$ok = has_capability("moodle/question:moveall", $context);
	if (!$ok)
		$ok = is_siteadmin();
	return $ok;
}
function RWSGetServiceOption($name)
{
	global $RWS_ENABLE_CAS_AUTH;
	if (isset($_POST[$name])) {
		if (get_magic_quotes_gpc())
			return stripslashes($_POST[$name]);
		else
			return $_POST[$name];
	}
	if ($RWS_ENABLE_CAS_AUTH) {
		if (!isloggedin()) {
			if (isset($_GET[$name])) {
				if (get_magic_quotes_gpc())
					return stripslashes($_GET[$name]);
				else
					return $_GET[$name];
			}
		}
	}
	if (isloggedin()) {
		if (isset($_FILES[$name]))
		{
			if ($_FILES[$name]['error'] == UPLOAD_ERR_OK )
			{
				$file = new stdClass();
				$file->filename = $_FILES[$name]['name'];
				$file->filedata = file_get_contents($_FILES[$name]['tmp_name']);
				return $file;
			}
		}
	}
	return FALSE;
}
function RWSSetQuizDefaultsLocal(&$quiz)
{
	global $DB;
	global $CFG;
	if (!empty($quiz->coursemodule)) {
		$context = get_context_instance(CONTEXT_MODULE, $quiz->coursemodule);
		$contextid = $context->id;
	} else if (!empty($quiz->course)) {
		$context = get_context_instance(CONTEXT_COURSE, $quiz->course);
		$contextid = $context->id;
	} else {
		$contextid = null;
	}
	$quiz->intro = "";
	$quiz->introformat = FORMAT_HTML;
	$quiz->timeopen = 0; 
	$quiz->timeclose = 0; 
	$quiz->timelimitenable = 0; 
	$quiz->timelimit = 0; 
	$quiz->attempts = 0; 
	$quiz->grademethod = 1; 
	$quiz->questionsperpage = 0; 
	$quiz->shufflequestions = 0; 
	$quiz->shuffleanswers = 1; 
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->preferredbehaviour = "adaptive";
	}
	else { 
		$quiz->adaptive = 1; 
		$quiz->penaltyscheme = 1; 
	}
	$quiz->attemptonlast = 0; 
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptduring = 1;				
		$quiz->correctnessduring = 1;			
		$quiz->marksduring = 1;					
		$quiz->specificfeedbackduring = 1;		
		$quiz->generalfeedbackduring = 1;		
		$quiz->rightanswerduring = 1;			
		$quiz->overallfeedbackduring = 1;		
	}
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptimmediately = 1;			
		$quiz->correctnessimmediately = 1;		
		$quiz->marksimmediately = 1;			
		$quiz->specificfeedbackimmediately = 1;	
		$quiz->generalfeedbackimmediately = 1;	
		$quiz->rightanswerimmediately = 1;		
		$quiz->overallfeedbackimmediately = 1;	
	}
	else { 
		$quiz->responsesimmediately = 1;		
		$quiz->answersimmediately = 1;			
		$quiz->feedbackimmediately = 1;			
		$quiz->generalfeedbackimmediately = 1;	
		$quiz->scoreimmediately = 1;			
		$quiz->overallfeedbackimmediately = 1;	
	}
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptopen = 1;				
		$quiz->correctnessopen = 1;			
		$quiz->marksopen = 1;				
		$quiz->specificfeedbackopen = 1;	
		$quiz->generalfeedbackopen = 1;		
		$quiz->rightansweropen = 1;			
		$quiz->overallfeedbackopen = 1;		
	}
	else { 
		$quiz->responsesopen = 1;		
		$quiz->answersopen = 1;			
		$quiz->feedbackopen = 1;		
		$quiz->generalfeedbackopen = 1;	
		$quiz->scoreopen = 1;			
		$quiz->overallfeedbackopen = 1;	
	}
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptclosed = 1;			
		$quiz->correctnessclosed = 1;		
		$quiz->marksclosed = 1;				
		$quiz->specificfeedbackclosed = 1;	
		$quiz->generalfeedbackclosed = 1;	
		$quiz->rightanswerclosed = 1;		
		$quiz->overallfeedbackclosed = 1;	
	}
	else { 
		$quiz->responsesclosed = 1;			
		$quiz->answersclosed = 1;			
		$quiz->feedbackclosed = 1;			
		$quiz->generalfeedbackclosed = 1;	
		$quiz->scoreclosed = 1;				
		$quiz->overallfeedbackclosed = 1;	
	}
	$quiz->showuserpicture = 0; 
	$quiz->decimalpoints = 2; 
	$quiz->questiondecimalpoints = -1; 
	$quiz->showblocks = 0; 
	$quiz->quizpassword = ""; 
	$quiz->subnet = ""; 
	$quiz->delay1 = 0; 
	$quiz->delay2 = 0; 
	$quiz->popup = 0; 
	$num_feeds = 5; 
	for ($i = 0; $i < $num_feeds; $i++) {
		$draftid = 0;
		$component = "mod_quiz";
		$filearea = "feedback";
		$itemid = null;
		$options = null;
		$text = ""; 
		$quiz->feedbacktext[$i]["text"] = file_prepare_draft_area(
		  $draftid, $contextid, $component, $filearea, $itemid, $options, $text
		  );
		$quiz->feedbacktext[$i]["format"] = FORMAT_HTML;
		$quiz->feedbacktext[$i]["itemid"] = $draftid;
		if ($i < $num_feeds - 1)
			$quiz->feedbackboundaries[$i] = ""; 
	}
	$quiz->groupmode = NOGROUPS; 
	$quiz->groupingid = 0; 
	$quiz->visible = 1; 
	$quiz->cmidnumber = ""; 
	if (!empty($quiz->course)) {
		$course = $DB->get_record("course", array("id" => $quiz->course));
		if ($course !== FALSE && $course->groupmodeforce) {
			$quiz->groupmode = $course->groupmode;
			$quiz->groupingid = $course->defaultgroupingid;
		}
	}
	$quiz->grade = 10; 
}
function RWSSetQuizDefaultsMoodle(&$quiz)
{
	global $DB;
	global $CFG;
	if (!empty($quiz->coursemodule)) {
		$context = get_context_instance(CONTEXT_MODULE, $quiz->coursemodule);
		$contextid = $context->id;
	} else if (!empty($quiz->course)) {
		$context = get_context_instance(CONTEXT_COURSE, $quiz->course);
		$contextid = $context->id;
	} else {
		$contextid = null;
	}
	$defaults = get_config("quiz");
	$quiz->intro = ""; 
	$quiz->introformat = FORMAT_HTML;
	$quiz->timeopen = 0;  
	$quiz->timeclose = 0; 
	if ($defaults->timelimit > 0)
		$quiz->timelimitenable = 1;
	else
		$quiz->timelimitenable = 0;
	$quiz->timelimit = $defaults->timelimit;
	$quiz->attempts = $defaults->attempts;
	$quiz->grademethod = $defaults->grademethod;
	$quiz->questionsperpage = $defaults->questionsperpage;
	$quiz->shufflequestions = $defaults->shufflequestions;
	$quiz->shuffleanswers = $defaults->shuffleanswers;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->preferredbehaviour = $defaults->preferredbehaviour;
	}
	else { 
		$quiz->adaptive = $defaults->optionflags & RWS_QUESTION_ADAPTIVE;
		$quiz->penaltyscheme = $defaults->penaltyscheme;
	}
	$quiz->attemptonlast = $defaults->attemptonlast;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptduring = $defaults->reviewattempt & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->attemptduring)
			unset($quiz->attemptduring);
		$quiz->correctnessduring = $defaults->reviewcorrectness & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->correctnessduring)
			unset($quiz->correctnessduring);
		$quiz->marksduring = $defaults->reviewmarks & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->marksduring)
			unset($quiz->marksduring);
		$quiz->specificfeedbackduring = $defaults->reviewspecificfeedback & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->specificfeedbackduring)
			unset($quiz->specificfeedbackduring);
		$quiz->generalfeedbackduring = $defaults->reviewgeneralfeedback & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->generalfeedbackduring)
			unset($quiz->generalfeedbackduring);
		$quiz->rightanswerduring = $defaults->reviewrightanswer & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->rightanswerduring)
			unset($quiz->rightanswerduring);
		$quiz->overallfeedbackduring = $defaults->reviewoverallfeedback & RWS_QUIZ_REVIEW_DURING;
		if (!$quiz->overallfeedbackduring)
			unset($quiz->overallfeedbackduring);
	}
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptimmediately = $defaults->reviewattempt & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->attemptimmediately)
			unset($quiz->attemptimmediately);
		$quiz->correctnessimmediately = $defaults->reviewcorrectness & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->correctnessimmediately)
			unset($quiz->correctnessimmediately);
		$quiz->marksimmediately = $defaults->reviewmarks & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->marksimmediately)
			unset($quiz->marksimmediately);
		$quiz->specificfeedbackimmediately = $defaults->reviewspecificfeedback & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->specificfeedbackimmediately)
			unset($quiz->specificfeedbackimmediately);
		$quiz->generalfeedbackimmediately = $defaults->reviewgeneralfeedback & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->generalfeedbackimmediately)
			unset($quiz->generalfeedbackimmediately);
		$quiz->rightanswerimmediately = $defaults->reviewrightanswer & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->rightanswerimmediately)
			unset($quiz->rightanswerimmediately);
		$quiz->overallfeedbackimmediately = $defaults->reviewoverallfeedback & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER;
		if (!$quiz->overallfeedbackimmediately)
			unset($quiz->overallfeedbackimmediately);
	}
	else { 
		$quiz->responsesimmediately = $defaults->review & RWS_QUIZ_REVIEW_RESPONSES & RWS_QUIZ_REVIEW_IMMEDIATELY;
		if (!$quiz->responsesimmediately)
			unset($quiz->responsesimmediately);
		$quiz->answersimmediately = $defaults->review & RWS_QUIZ_REVIEW_ANSWERS & RWS_QUIZ_REVIEW_IMMEDIATELY;
		if (!$quiz->answersimmediately)
			unset($quiz->answersimmediately);
		$quiz->feedbackimmediately = $defaults->review & RWS_QUIZ_REVIEW_FEEDBACK & RWS_QUIZ_REVIEW_IMMEDIATELY;
		if (!$quiz->feedbackimmediately)
			unset($quiz->feedbackimmediately);
		$quiz->generalfeedbackimmediately = $defaults->review & RWS_QUIZ_REVIEW_GENERALFEEDBACK & RWS_QUIZ_REVIEW_IMMEDIATELY;
		if (!$quiz->generalfeedbackimmediately)
			unset($quiz->generalfeedbackimmediately);
		$quiz->scoreimmediately = $defaults->review & RWS_QUIZ_REVIEW_SCORES & RWS_QUIZ_REVIEW_IMMEDIATELY;
		if (!$quiz->scoreimmediately)
			unset($quiz->scoreimmediately);
		$quiz->overallfeedbackimmediately = $defaults->review & RWS_QUIZ_REVIEW_OVERALLFEEDBACK & RWS_QUIZ_REVIEW_IMMEDIATELY;
		if (!$quiz->overallfeedbackimmediately)
			unset($quiz->overallfeedbackimmediately);
	}
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptopen = $defaults->reviewattempt & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->attemptopen)
			unset($quiz->attemptopen);
		$quiz->correctnessopen = $defaults->reviewcorrectness & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->correctnessopen)
			unset($quiz->correctnessopen);
		$quiz->marksopen = $defaults->reviewmarks & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->marksopen)
			unset($quiz->marksopen);
		$quiz->specificfeedbackopen = $defaults->reviewspecificfeedback & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->specificfeedbackopen)
			unset($quiz->specificfeedbackopen);
		$quiz->generalfeedbackopen = $defaults->reviewgeneralfeedback & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->generalfeedbackopen)
			unset($quiz->generalfeedbackopen);
		$quiz->rightansweropen = $defaults->reviewrightanswer & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->rightansweropen)
			unset($quiz->rightansweropen);
		$quiz->overallfeedbackopen = $defaults->reviewoverallfeedback & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN;
		if (!$quiz->overallfeedbackopen)
			unset($quiz->overallfeedbackopen);
	}
	else { 
		$quiz->responsesopen = $defaults->review & RWS_QUIZ_REVIEW_RESPONSES & RWS_QUIZ_REVIEW_OPEN;
		if (!$quiz->responsesopen)
			unset($quiz->responsesopen);
		$quiz->answersopen = $defaults->review & RWS_QUIZ_REVIEW_ANSWERS & RWS_QUIZ_REVIEW_OPEN;
		if (!$quiz->answersopen)
			unset($quiz->answersopen);
		$quiz->feedbackopen = $defaults->review & RWS_QUIZ_REVIEW_FEEDBACK & RWS_QUIZ_REVIEW_OPEN;
		if (!$quiz->feedbackopen)
			unset($quiz->feedbackopen);
		$quiz->generalfeedbackopen = $defaults->review & RWS_QUIZ_REVIEW_GENERALFEEDBACK & RWS_QUIZ_REVIEW_OPEN;
		if (!$quiz->generalfeedbackopen)
			unset($quiz->generalfeedbackopen);
		$quiz->scoreopen = $defaults->review & RWS_QUIZ_REVIEW_SCORES & RWS_QUIZ_REVIEW_OPEN;
		if (!$quiz->scoreopen)
			unset($quiz->scoreopen);
		$quiz->overallfeedbackopen = $defaults->review & RWS_QUIZ_REVIEW_OVERALLFEEDBACK & RWS_QUIZ_REVIEW_OPEN;
		if (!$quiz->overallfeedbackopen)
			unset($quiz->overallfeedbackopen);
	}
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptclosed = $defaults->reviewattempt & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->attemptclosed)
			unset($quiz->attemptclosed);
		$quiz->correctnessclosed = $defaults->reviewcorrectness & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->correctnessclosed)
			unset($quiz->correctnessclosed);
		$quiz->marksclosed = $defaults->reviewmarks & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->marksclosed)
			unset($quiz->marksclosed);
		$quiz->specificfeedbackclosed = $defaults->reviewspecificfeedback & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->specificfeedbackclosed)
			unset($quiz->specificfeedbackclosed);
		$quiz->generalfeedbackclosed = $defaults->reviewgeneralfeedback & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->generalfeedbackclosed)
			unset($quiz->generalfeedbackclosed);
		$quiz->rightanswerclosed = $defaults->reviewrightanswer & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->rightanswerclosed)
			unset($quiz->rightanswerclosed);
		$quiz->overallfeedbackclosed = $defaults->reviewoverallfeedback & RWS_QUIZ_REVIEW_AFTER_CLOSE;
		if (!$quiz->overallfeedbackclosed)
			unset($quiz->overallfeedbackclosed);
	}
	else { 
		$quiz->responsesclosed = $defaults->review & RWS_QUIZ_REVIEW_RESPONSES & RWS_QUIZ_REVIEW_CLOSED;
		if (!$quiz->responsesclosed)
			unset($quiz->responsesclosed);
		$quiz->answersclosed = $defaults->review & RWS_QUIZ_REVIEW_ANSWERS & RWS_QUIZ_REVIEW_CLOSED;
		if (!$quiz->answersclosed)
			unset($quiz->answersclosed);
		$quiz->feedbackclosed = $defaults->review & RWS_QUIZ_REVIEW_FEEDBACK & RWS_QUIZ_REVIEW_CLOSED;
		if (!$quiz->feedbackclosed)
			unset($quiz->feedbackclosed);
		$quiz->generalfeedbackclosed = $defaults->review & RWS_QUIZ_REVIEW_GENERALFEEDBACK & RWS_QUIZ_REVIEW_CLOSED;
		if (!$quiz->generalfeedbackclosed)
			unset($quiz->generalfeedbackclosed);
		$quiz->scoreclosed = $defaults->review & RWS_QUIZ_REVIEW_SCORES & RWS_QUIZ_REVIEW_CLOSED;
		if (!$quiz->scoreclosed)
			unset($quiz->scoreclosed);
		$quiz->overallfeedbackclosed = $defaults->review & RWS_QUIZ_REVIEW_OVERALLFEEDBACK & RWS_QUIZ_REVIEW_CLOSED;
		if (!$quiz->overallfeedbackclosed)
			unset($quiz->overallfeedbackclosed);
	}
	$quiz->showuserpicture = $defaults->showuserpicture;
	$quiz->decimalpoints = $defaults->decimalpoints;
	$quiz->questiondecimalpoints = $defaults->questiondecimalpoints;
	$quiz->showblocks = $defaults->showblocks;
	$quiz->quizpassword = $defaults->password;
	$quiz->subnet = $defaults->subnet;
	$quiz->delay1 = $defaults->delay1;
	$quiz->delay2 = $defaults->delay2;
	$quiz->popup = $defaults->popup;
	$num_feeds = 5; 
	for ($i = 0; $i < $num_feeds; $i++) {
		$draftid = 0;
		$component = "mod_quiz";
		$filearea = "feedback";
		$itemid = null;
		$options = null;
		$text = ""; 
		$quiz->feedbacktext[$i]["text"] = file_prepare_draft_area(
		  $draftid, $contextid, $component, $filearea, $itemid, $options, $text
		  );
		$quiz->feedbacktext[$i]["format"] = FORMAT_HTML;
		$quiz->feedbacktext[$i]["itemid"] = $draftid;
		if ($i < $num_feeds - 1)
			$quiz->feedbackboundaries[$i] = ""; 
	}
	$quiz->groupmode = NOGROUPS;
	$quiz->groupingid = 0;
	$quiz->visible = 1;
	$quiz->cmidnumber = ""; 
	if (!empty($quiz->course)) {
		$course = $DB->get_record("course", array("id" => $quiz->course));
		if ($course !== FALSE) {
			$quiz->groupmode = $course->groupmode;
			$quiz->groupingid = $course->defaultgroupingid;
			if (!empty($quiz->section)) {
				$section = get_course_section($quiz->section, $quiz->course);
				$quiz->visible = $section->visible;
			}
		}
	}
	$quiz->grade = $defaults->maximumgrade;
}
function RWSSetQuizDefaults(&$quiz, $process_options=FALSE)
{
	global $RWS_LDB_INFO;
		RWSSetQuizDefaultsMoodle($quiz);
	$RWS_LDB_INFO->attempts = 0; 
	$RWS_LDB_INFO->reviews = 0; 
	$RWS_LDB_INFO->password = ""; 
	if ($process_options) {
		if (is_null($quiz->quizpassword) && !is_null($quiz->password))
			$quiz->quizpassword = $quiz->password;
		quiz_process_options($quiz);
	}
}
function RWSImportQuizSettings(
  &$quiz, $sfile, $sdata, $encoded, $process_options=FALSE)
{
	$clean_import_dir = FALSE;
	$clean_import_file = FALSE;
	$close_import_file = FALSE;
	if ($encoded) {
		$decoded = base64_decode($sdata);
		if ($decoded === FALSE) {
			RWSServiceError("2017");
		}
	}
	else { 
		$decoded = $sdata;
	}
	$import_dir = RWSMakeTempFolder();
	$ok = ($import_dir !== FALSE);
	$clean_import_dir = $ok;
	if (!$ok) 
		$error = "2018";
	if ($ok) {
		$ok = RWSDecompressImportData($decoded, $import_dir);
		if (!$ok) 
			$error = "2019";
	}
	if ($ok) {
		$pos = strrpos($sfile, ".");
		$ok = ($pos !== FALSE && $pos !== 0);
		if (!$ok) 
			$error = "2020"; 
	}
	if ($ok) {
		$import_file = "$import_dir/";
		if ($pos === FALSE) 
			$import_file .= $sfile;
		else 
			$import_file .= substr($sfile, 0, $pos);
		$import_file .= ".dat";
		$ok = file_exists($import_file);
		$clean_import_file = $ok;
		if (!$ok)
			$error = "2020"; 
	}
	if ($ok) {
		$handle = fopen($import_file, "rb");
		$ok = ($handle !== FALSE);
		$close_import_file = $ok;
		if (!$ok)
			$error = "2021"; 
	}
	if ($ok) {
		$ok = RWSCheckSettingsFileSignature($handle);
		if (!$ok)
			$error = "2022"; 
	}
	if ($ok) {
		$ok = RWSCheckSettingsFileVersion($handle);
		if (!$ok)
			$error = "2023"; 
	}	
	if ($ok) {
		$record = RWSReadSettingsRecord($handle);
		$ok = ($record !== FALSE);
		if (!$ok)
			$error = "2024"; 
	}
	if ($ok) {
		$ok = RWSImportSettingsRecord($quiz, $record, $process_options);
		if (!$ok)
			$error = "2025"; 
	}
	if ($close_import_file)
		fclose($handle);
	if ($clean_import_file && file_exists($import_file))
		unlink($import_file);
	if ($clean_import_dir && file_exists($import_dir))
		rmdir($import_dir);
	if (!$ok)
		RWSServiceError($error);
}
function RWSExportQuizSettings($quiz, &$sfile, $want_base64)
{
		$format_version = 0; 
	$fname_compressed = "rwsexportsdata.zip";
	$fname_uncompressed = "rwsexportsdata.dat";
	$sfile = "";
	$clean_export_dir = FALSE;
	$clean_export_file = FALSE;
	$clean_compressed_file = FALSE;
	$close_export_file = FALSE;
	$ok = TRUE;
	if ($ok) {
		$export_dir = RWSMakeTempFolder();
		$ok = ($export_dir !== FALSE);
		$clean_export_dir = $ok;
		if (!$ok) 
			$error = "2026";
	}
	if ($ok) {
		$export_file = "$export_dir/$fname_uncompressed";
		$handle = fopen($export_file, "wb"); 
		$ok = ($handle !== FALSE);
		$clean_export_file = $ok;
		$close_export_file = $ok;
		if (!$ok)
			$error = "2027"; 
	}
	if ($ok) {
			$data = pack("C*", 0x21, 0xfd, 0x65, 0x0d, 0x6e, 0xae, 0x4d, 0x01,
			  0x86, 0x78, 0xf5, 0x13, 0x00, 0x86, 0x99, 0x2a);
		$data .= pack("n", $format_version);
		$bytes = fwrite($handle, $data);
		$ok = ($bytes !== FALSE);
		if (!$ok)
			$error = "2028"; 
	}
	if ($ok) {
		$record = RWSExportSettingsRecord($quiz);
		$ok = ($record !== FALSE);
		if (!$ok)
			$error = "2029"; 
    }
	if ($ok) {
		$ok = RWSWriteSettingsRecord($handle, $record);
		if (!$ok)
			$error = "2028"; 
	}
	if ($close_export_file)
		fclose($handle);
	if ($ok) {
		$compressed_file = "$export_dir/$fname_compressed";
		$ok = RWSCompressExportData($export_file, $compressed_file);
		$clean_compressed_file = $ok;
		if (!$ok)
			$error = "2031"; 
	}
	if ($ok) {
		$compressed = file_get_contents($compressed_file);
		$ok = ($compressed !== FALSE);
		if (!$ok)
			$error = "2032"; 
	}
	if ($ok && $want_base64)
		$encoded = base64_encode($compressed);
	if ($clean_export_file && file_exists($export_file))
		unlink($export_file);
	if ($clean_compressed_file && file_exists($compressed_file))
		unlink($compressed_file);
	if ($clean_export_dir && file_exists($export_dir))
		rmdir($export_dir);
	if (!$ok)
		RWSServiceError($error);
	$sfile = $fname_compressed;
	if ($want_base64)
		return $encoded;
	else
		return $compressed;
}
function RWSImportQuestions(
  $course_id, $qcat_id, $qfile, $qdata, $encoded, &$dropped, &$badatts)
{
	$imported = 0;
	$dropped = 0;
	$badatts = 0;
	$badresv = 0;
	$clean_import_dir = FALSE;
	$clean_import_file = FALSE;
	$close_import_file = FALSE;
	if ($encoded) {
		$decoded = base64_decode($qdata);
		if ($decoded === FALSE) {
			RWSServiceError("2033");
		}
	}
	else { 
		$decoded = $qdata;
	}
	$import_dir = RWSMakeTempFolder();
	$ok = ($import_dir !== FALSE);
	$clean_import_dir = $ok;
	if (!$ok)
		$error = "2034"; 
	if ($ok) {
		$ok = RWSDecompressImportData($decoded, $import_dir);
		if (!$ok)
			$error = "2035"; 
	}
	if ($ok) {
		$pos = strrpos($qfile, ".");
		$ok = ($pos !== FALSE && $pos !== 0);
		if (!$ok) 
			$error = "2036"; 
	}
	if ($ok) {
		$import_file = "$import_dir/";
		if ($pos === FALSE) 
			$import_file .= $qfile;
		else 
			$import_file .= substr($qfile, 0, $pos);
		$import_file .= ".dat";
		$ok = file_exists($import_file);
		$clean_import_file = $ok;
		if (!$ok)
			$error = "2036"; 
	}
	if ($ok) {
		$handle = fopen($import_file, "rb");
		$ok = ($handle !== FALSE);
		$close_import_file = $ok;
		if (!$ok)
			$error = "2037"; 
	}
	if ($ok) {
		$ok = RWSCheckQuestionFileSignature($handle);
		if (!$ok)
			$error = "2038"; 
	}
	if ($ok) {
		$ok = RWSCheckQuestionFileVersion($handle);
		if (!$ok)
			$error = "2039"; 
	}	
	if ($ok) {
		$question_ids = array();
		$record = RWSReadNextQuestionRecord($handle);
		while ($record !== FALSE) {
			$type = RWSGetQuestionRecordType($record);
			switch ($type) {
			case RWS_ATTACHMENT:
				$subpath = RWSImportAttachmentRecord($course_id, $qcat_id, $record);
				break;
			case RWS_SHORTANSWER:
				$qid = RWSImportShortAnswerRecord($course_id, $qcat_id, $record);
				break;
			case RWS_TRUEFALSE:
				$qid = RWSImportTrueFalseRecord($course_id, $qcat_id, $record);
				break;
			case RWS_MULTICHOICE:
				$qid = RWSImportMultipleChoiceRecord($course_id, $qcat_id, $record);
				break;
			case RWS_MATCH:
				$qid = RWSImportMatchingRecord($course_id, $qcat_id, $record);
				break;
			case RWS_DESCRIPTION:
				$qid = RWSImportDescriptionRecord($course_id, $qcat_id, $record);
				break;
			case RWS_ESSAY:
				$qid = RWSImportEssayRecord($course_id, $qcat_id, $record);
				break;
			case RWS_CALCULATED:
				$qid = RWSImportCalculatedRecord($course_id, $qcat_id, $record);
				break;
			case RWS_MULTIANSWER: 
				$qid = RWSImportMultiAnswerRecord($course_id, $qcat_id, $record);
				break;
			case RWS_RESERVED:
				$result = RWSImportReservedRecord($course_id, $qcat_id, $record);
				break;
			case RWS_CALCULATEDSIMPLE:
			case RWS_CALCULATEDMULTI:
			case RWS_RANDOM:
			case RWS_NUMERICAL:
			case RWS_RANDOMSAMATCH:
			case RWS_UNKNOWN:
			default:
				$qid = FALSE;
				break;
			}
			if ($type == RWS_ATTACHMENT) {
				if ($subpath === FALSE)
					$badatts++;
			}
			else if ($type == RWS_RESERVED) {
				if ($result === FALSE)
					$badresv++;
			}
			else { 
				if ($qid === FALSE)
					$dropped++;
				else {
					$imported++;
					$question_ids[] = $qid;
				}
			}
			$record = RWSReadNextQuestionRecord($handle);
		}
	}
	if ($close_import_file)
		fclose($handle);
	if ($clean_import_file && file_exists($import_file))
		unlink($import_file);
	if ($clean_import_dir && file_exists($import_dir))
		rmdir($import_dir);
	if (!$ok)
		RWSServiceError($error);
	if ($imported == 0) {
		if ($dropped == 0) 
			RWSServiceError("2040");
		else 
			RWSServiceError("2041");
	}
	return $question_ids;
}
function RWSCheckQuestionFileSignature($handle)
{
	$expected_sig =	array(0xe1, 0x8a, 0x3b, 0xaf, 0xd0, 0x30, 0x4d, 0xce,
	  0xb4, 0x75, 0x8a, 0xdf, 0x1e, 0xa9, 0x08, 0x36);
	if (feof($handle))
		return FALSE;
	$buffer = fread($handle, 16);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$actual_sig = array_values(unpack("C*", $buffer));
	$count = count($expected_sig);
	if ($count != count($actual_sig))
		return FALSE;
	for($i = 0; $i < $count; $i++) {
		if ($actual_sig[$i] != $expected_sig[$i])
			return FALSE;		
	}
	return TRUE;
}
function RWSCheckSettingsFileSignature($handle)
{
	$expected_sig =	array(0x07, 0x0b, 0x28, 0x3a, 0x98, 0xfa, 0x4c, 0xcd,
	  0x8a, 0x62, 0x14, 0xa7, 0x97, 0x33, 0x84, 0x37);
	if (feof($handle))
		return FALSE;
	$buffer = fread($handle, 16);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$actual_sig = array_values(unpack("C*", $buffer));
	$count = count($expected_sig);
	if ($count != count($actual_sig))
		return FALSE;
	for($i = 0; $i < $count; $i++) {
		if ($actual_sig[$i] != $expected_sig[$i])
			return FALSE;		
	}
	return TRUE;
}
function RWSCheckQuestionFileVersion($handle)
{
	$expected_version = 0; 
	if (feof($handle))
		return FALSE;
	$buffer = fread($handle, 2);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$data = unpack("n", $buffer);
	$actual_version = $data[1];
	if ($actual_version == $expected_version)
		return TRUE;
	else
		return FALSE;
}
function RWSCheckSettingsFileVersion($handle)
{
	$expected_version = 0; 
	if (feof($handle))
		return FALSE;
	$buffer = fread($handle, 2);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$data = unpack("n", $buffer);
	$actual_version = $data[1];
	if ($actual_version == $expected_version)
		return TRUE;
	else
		return FALSE;
}
function RWSReadSettingsRecord($handle)
{
	if (feof($handle))
		return FALSE;
	$curr_pos = ftell($handle);
	if(fseek($handle, 0, SEEK_END) != 0)
		return FALSE;
	$end_pos = ftell($handle);
	$size = $end_pos - $curr_pos;
	if(fseek($handle, $curr_pos, SEEK_SET) != 0)
		return FALSE;
	$record = fread($handle, $size);
	if ($record === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	for ($i = 0; $i < $size; $i++) {
		$data = unpack("C", $record[$i]);
		$n = (intval($data[1]) ^ 0x55) - 1;
		if ($n < 0)
			$n = 255;
		$record[$i] = pack("C", $n);
	}
	return $record;
}
function RWSWriteSettingsRecord($handle, $record)
{
	$ok = TRUE;
	$len = strlen($record);
	for ($i = 0; $i < $len; $i++) {
		$data = unpack("C", $record[$i]);
			$n = intval($data[1]) - 1;
			if ($n < 0)
				$n = 255;
			$n ^= 0xaa;
		$record[$i] = pack("C", $n);
	}
	if ($len > 0) {
		$bytes = fwrite($handle, $record);
		$ok = ($bytes !== FALSE);
	}
	return $ok;
}
function RWSReadNextQuestionRecord($handle)
{
	$record = "";
	if (feof($handle))
		return FALSE;
	$buffer = fread($handle, 1);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$record .= $buffer;
	$buffer = fread($handle, 4);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$record .= $buffer;
	$size = strlen($buffer);
	for ($i = 0; $i < $size; $i++) {
		$data = unpack("C", $buffer[$i]);
		$n = (intval($data[1]) ^ 0x55) - 1;
		if ($n < 0)
			$n = 255;
		$buffer[$i] = pack("C", $n);
	}
	$data = unpack("N", $buffer);
	$size = $data[1];
	if ($size < 1)
		return FALSE;
	$buffer = fread($handle, $size);
	if ($buffer === FALSE)
		return FALSE;
	if (feof($handle))
		return FALSE;
	$record .= $buffer;
	$size = strlen($record); 
	for ($i = 0; $i < $size; $i++) {
		$data = unpack("C", $record[$i]);
		$n = (intval($data[1]) ^ 0x55) - 1;
		if ($n < 0)
			$n = 255;
		$record[$i] = pack("C", $n);
	}
	return $record;
}
function RWSWriteNextQuestionRecord($handle, $record)
{
	$ok = TRUE;
	$len = strlen($record);
	for ($i = 0; $i < $len; $i++) {
		$data = unpack("C", $record[$i]);
			$n = intval($data[1]) - 1;
			if ($n < 0)
				$n = 255;
			$n ^= 0xaa;
		$record[$i] = pack("C", $n);
	}
	if ($len > 0) {
		$bytes = fwrite($handle, $record);
		$ok = ($bytes !== FALSE);
	}
	return $ok;
}
function RWSGetQuestionRecordType($record)
{
	$data = unpack("C", $record[0]);
	$type = intval($data[1]);
	switch ($type) {
	case 0:
		return RWS_ATTACHMENT;
	case 1:
		return RWS_MULTICHOICE;
	case 2:
		return RWS_TRUEFALSE;
	case 3:
		return RWS_SHORTANSWER;
	case 4:
		return RWS_ESSAY;
	case 5:
		return RWS_MATCH;
	case 6:
		return RWS_DESCRIPTION;
	case 7:
		return RWS_CALCULATED;
	case 8:
		return RWS_NUMERICAL;
	case 9:  
		return RWS_MULTIANSWER;
	case 10: 
		return RWS_RANDOM;
	case 11:
		return RWS_RANDOMSAMATCH;
	case 12:
		return RWS_RESERVED;
	case 13:
		return RWS_CALCULATEDSIMPLE;
	case 14:
		return RWS_CALCULATEDMULTI;
	default:
		return RWS_UNKNOWN;
	}
}
function RWSGetDaysInMonth($month, $year)
{
	switch ($month) {
	case 1:
	case 3:
	case 5:
	case 7:
	case 8:
	case 10:
	case 12:
		return 31;
	case 4:
	case 6:
	case 9:
	case 11:
		return 30;
	case 2:
		if ($year % 400 == 0)
			return 29;
		else if ($year % 100 == 0)
			return 28;
		else if ($year % 4 == 0)
			return 29;
		else
			return 28;
	default:
		return FALSE;
	}
}
function RWSImportSettingsRecord(&$quiz, $record, $process_options=FALSE)
{
	global $RWS_LDB_INFO;
	global $CFG;
	$pos = 0;
	$size = strlen($record);
	if (!empty($quiz->coursemodule)) {
		$context = get_context_instance(CONTEXT_MODULE, $quiz->coursemodule);
		$contextid = $context->id;
	} else if (!empty($quiz->course)) {
		$context = get_context_instance(CONTEXT_COURSE, $quiz->course);
		$contextid = $context->id;
	} else {
		$contextid = null;
	}
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$quiz->intro = trim($field); 
	$quiz->introformat = FORMAT_HTML;
	$count = 2;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("n", $field);
	$year = $data[1];
	if ($year != 0 && ($year < 1970 || $year > 2020))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$month = intval($data[1]);
	if ($year != 0 && ($month < 1 || $month > 12))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$day = intval($data[1]);
	if ($year != 0 && ($day < 1 || $day > RWSGetDaysInMonth($month, $year)))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$hour = intval($data[1]);
	if ($year != 0 && ($hour < 0 || $hour > 23))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$minute = intval($data[1]);
	if ($year != 0 && ($minute < 0 || $minute > 55 || $minute % 5 != 0))
		return FALSE;
	if ($year == 0)
		$quiz->timeopen = 0;
	else
		$quiz->timeopen = make_timestamp($year, $month, $day, $hour, $minute);
	$count = 2;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("n", $field);
	$year = $data[1];
	if ($year != 0 && ($year < 1970 || $year > 2020))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$month = intval($data[1]);
	if ($year != 0 && ($month < 1 || $month > 12))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$day = intval($data[1]);
	if ($year != 0 && ($day < 1 || $day > RWSGetDaysInMonth($month, $year)))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$hour = intval($data[1]);
	if ($year != 0 && ($hour < 0 || $hour > 23))
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$minute = intval($data[1]);
	if ($year != 0 && ($minute < 0 || $minute > 55 || $minute % 5 != 0))
		return FALSE;
	if ($year == 0)
		$quiz->timeclose = 0;
	else
		$quiz->timeclose = make_timestamp($year, $month, $day, $hour, $minute);
	if ($quiz->timeopen != 0 && $quiz->timeclose != 0
	  && $quiz->timeopen > $quiz->timeclose)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->timelimitenable = intval($data[1]);
	if ($quiz->timelimitenable != 0 && $quiz->timelimitenable != 1)
		return FALSE;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$quiz->timelimit = $data[1] * 60; 
	if ($quiz->timelimitenable == 0)
		$quiz->timelimit = 0; 
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$quiz->delay1 = $data[1];
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$quiz->delay2 = $data[1];
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->questionsperpage = intval($data[1]);
	if ($quiz->questionsperpage < 0 || $quiz->questionsperpage > 50)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->shufflequestions = intval($data[1]);
	if ($quiz->shufflequestions != 0 && $quiz->shufflequestions != 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->shuffleanswers = intval($data[1]);
	if ($quiz->shuffleanswers != 0 && $quiz->shuffleanswers != 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->attempts = intval($data[1]);
	if ($quiz->attempts < 0 || $quiz->attempts > 10)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->attemptonlast = intval($data[1]);
	if ($quiz->attemptonlast != 0 && $quiz->attemptonlast != 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$adaptive = intval($data[1]);
	if ($adaptive != 0 && $adaptive != 1)
		return FALSE;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$quiz->grade = $data[1];
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->grademethod = intval($data[1]);
	switch ($quiz->grademethod) {
	case 1: 
	case 2: 
	case 3: 
	case 4: 
		break;
	default:
		return FALSE;
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$penaltyscheme = intval($data[1]);
	if ($penaltyscheme != 0 && $penaltyscheme != 1)
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		if ($adaptive == 0 && $penaltyscheme == 0)
			$quiz->preferredbehaviour = "deferredfeedback";
		else if ($adaptive == 0 && $penaltyscheme == 1)
			$quiz->preferredbehaviour = "deferredfeedback";
		else if ($adaptive == 1 && $penaltyscheme == 0)
			$quiz->preferredbehaviour = "adaptivenopenalty";
		else if ($adaptive == 1 && $penaltyscheme == 1)
			$quiz->preferredbehaviour = "adaptive";
		else
			return FALSE;
	}
	else { 
		$quiz->adaptive = $adaptive;
		$quiz->penaltyscheme = $penaltyscheme;
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->decimalpoints = intval($data[1]);
	switch ($quiz->decimalpoints) {
	case 0:
	case 1:
	case 2:
	case 3:
	case 4:
	case 5:
		break;
	default:
		return FALSE;
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$responsesimmediately = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$answersimmediately = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$feedbackimmediately = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$generalfeedbackimmediately = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$scoreimmediately = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$overallfeedbackimmediately = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$responsesopen = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$answersopen = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$feedbackopen = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$generalfeedbackopen = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$scoreopen = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$overallfeedbackopen = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$responsesclosed = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$answersclosed = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$feedbackclosed = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$generalfeedbackclosed = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$scoreclosed = $setting;
	else
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$setting = intval($data[1]);
	if ($setting == 0 || $setting == 1)
		$overallfeedbackclosed = $setting;
	else
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$quiz->attemptduring = 1;
		if (!$quiz->attemptduring)
			unset($quiz->attemptduring);
		$quiz->correctnessduring = 1;
		if (!$quiz->correctnessduring)
			unset($quiz->correctnessduring);
		$quiz->marksduring = 1;
		if (!$quiz->marksduring)
			unset($quiz->marksduring);
		$quiz->specificfeedbackduring = $feedbackimmediately;
		if (!$quiz->specificfeedbackduring)
			unset($quiz->specificfeedbackduring);
		$quiz->generalfeedbackduring = $generalfeedbackimmediately;
		if (!$quiz->generalfeedbackduring)
			unset($quiz->generalfeedbackduring);
		$quiz->rightanswerduring = $answersimmediately;
		if (!$quiz->rightanswerduring)
			unset($quiz->rightanswerduring);
		$quiz->overallfeedbackduring = 0;
		if (!$quiz->overallfeedbackduring)
			unset($quiz->overallfeedbackduring);
		$quiz->attemptimmediately = $responsesimmediately;
		if (!$quiz->attemptimmediately)
			unset($quiz->attemptimmediately);
		$quiz->correctnessimmediately = $scoreimmediately;
		if (!$quiz->correctnessimmediately)
			unset($quiz->correctnessimmediately);
		$quiz->marksimmediately = $scoreimmediately;
		if (!$quiz->marksimmediately)
			unset($quiz->marksimmediately);
		$quiz->specificfeedbackimmediately = $feedbackimmediately;
		if (!$quiz->specificfeedbackimmediately)
			unset($quiz->specificfeedbackimmediately);
		$quiz->generalfeedbackimmediately = $generalfeedbackimmediately;
		if (!$quiz->generalfeedbackimmediately)
			unset($quiz->generalfeedbackimmediately);
		$quiz->rightanswerimmediately = $answersimmediately;
		if (!$quiz->rightanswerimmediately)
			unset($quiz->rightanswerimmediately);
		$quiz->overallfeedbackimmediately = $overallfeedbackimmediately;
		if (!$quiz->overallfeedbackimmediately)
			unset($quiz->overallfeedbackimmediately);
		$quiz->attemptopen = $responsesopen;
		if (!$quiz->attemptopen)
			unset($quiz->attemptopen);
		$quiz->correctnessopen = $scoreopen;
		if (!$quiz->correctnessopen)
			unset($quiz->correctnessopen);
		$quiz->marksopen = $scoreopen;
		if (!$quiz->marksopen)
			unset($quiz->marksopen);
		$quiz->specificfeedbackopen = $feedbackopen;
		if (!$quiz->specificfeedbackopen)
			unset($quiz->specificfeedbackopen);
		$quiz->generalfeedbackopen = $generalfeedbackopen;
		if (!$quiz->generalfeedbackopen)
			unset($quiz->generalfeedbackopen);
		$quiz->rightansweropen = $answersopen;
		if (!$quiz->rightansweropen)
			unset($quiz->rightansweropen);
		$quiz->overallfeedbackopen = $overallfeedbackopen;
		if (!$quiz->overallfeedbackopen)
			unset($quiz->overallfeedbackopen);
		$quiz->attemptclosed = $responsesclosed;
		if (!$quiz->attemptclosed)
			unset($quiz->attemptclosed);
		$quiz->correctnessclosed = $scoreclosed;
		if (!$quiz->correctnessclosed)
			unset($quiz->correctnessclosed);
		$quiz->marksclosed = $scoreclosed;
		if (!$quiz->marksclosed)
			unset($quiz->marksclosed);
		$quiz->specificfeedbackclosed = $feedbackclosed;
		if (!$quiz->specificfeedbackclosed)
			unset($quiz->specificfeedbackclosed);
		$quiz->generalfeedbackclosed = $generalfeedbackclosed;
		if (!$quiz->generalfeedbackclosed)
			unset($quiz->generalfeedbackclosed);
		$quiz->rightanswerclosed = $answersclosed;
		if (!$quiz->rightanswerclosed)
			unset($quiz->rightanswerclosed);
		$quiz->overallfeedbackclosed = $overallfeedbackclosed;
		if (!$quiz->overallfeedbackclosed)
			unset($quiz->overallfeedbackclosed);
	}
	else { 
		$quiz->responsesimmediately = $responsesimmediately;
		if (!$quiz->responsesimmediately)
			unset($quiz->responsesimmediately);
		$quiz->answersimmediately = $answersimmediately;
		if (!$quiz->answersimmediately)
			unset($quiz->answersimmediately);
		$quiz->feedbackimmediately = $feedbackimmediately;
		if (!$quiz->feedbackimmediately)
			unset($quiz->feedbackimmediately);
		$quiz->generalfeedbackimmediately = $generalfeedbackimmediately;
		if (!$quiz->generalfeedbackimmediately)
			unset($quiz->generalfeedbackimmediately);
		$quiz->scoreimmediately = $scoreimmediately;
		if (!$quiz->scoreimmediately)
			unset($quiz->scoreimmediately);
		$quiz->overallfeedbackimmediately = $overallfeedbackimmediately;
		if (!$quiz->overallfeedbackimmediately)
			unset($quiz->overallfeedbackimmediately);
		$quiz->responsesopen = $responsesopen;
		if (!$quiz->responsesopen)
			unset($quiz->responsesopen);
		$quiz->answersopen = $answersopen;
		if (!$quiz->answersopen)
			unset($quiz->answersopen);
		$quiz->feedbackopen = $feedbackopen;
		if (!$quiz->feedbackopen)
			unset($quiz->feedbackopen);
		$quiz->generalfeedbackopen = $generalfeedbackopen;
		if (!$quiz->generalfeedbackopen)
			unset($quiz->generalfeedbackopen);
		$quiz->scoreopen = $scoreopen;
		if (!$quiz->scoreopen)
			unset($quiz->scoreopen);
		$quiz->overallfeedbackopen = $overallfeedbackopen;
		if (!$quiz->overallfeedbackopen)
			unset($quiz->overallfeedbackopen);
		$quiz->responsesclosed = $responsesclosed;
		if (!$quiz->responsesclosed)
			unset($quiz->responsesclosed);
		$quiz->answersclosed = $answersclosed;
		if (!$quiz->answersclosed)
			unset($quiz->answersclosed);
		$quiz->feedbackclosed = $feedbackclosed;
		if (!$quiz->feedbackclosed)
			unset($quiz->feedbackclosed);
		$quiz->generalfeedbackclosed = $generalfeedbackclosed;
		if (!$quiz->generalfeedbackclosed)
			unset($quiz->generalfeedbackclosed);
		$quiz->scoreclosed = $scoreclosed;
		if (!$quiz->scoreclosed)
			unset($quiz->scoreclosed);
		$quiz->overallfeedbackclosed = $overallfeedbackclosed;
		if (!$quiz->overallfeedbackclosed)
			unset($quiz->overallfeedbackclosed);
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->popup = intval($data[1]);
	if ($quiz->popup != 0 && $quiz->popup != 1)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$quiz->quizpassword = trim($field); 
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$quiz->subnet = trim($field); 
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->groupmode = intval($data[1]);
	switch ($quiz->groupmode) {
	case 0: 
	case 1: 
	case 2: 
		break;
	default:
		return FALSE;
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$quiz->visible = intval($data[1]);
	if ($quiz->visible != 0 && $quiz->visible != 1)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$quiz->cmidnumber = trim($field); 
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_feeds = intval($data[1]);
	$feeds = array();
	for ($i = 0; $i < $num_feeds; $i++) {
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$feeds[] = trim($field); 
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_bounds = intval($data[1]);
	$bounds = array();
	for ($i = 0; $i < $num_bounds; $i++) {
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$bound = trim($field); 
		$len = strlen($bound);
		if ($len == 0)
			return FALSE;
		if (is_numeric($bound)) {
			if ($bound <= 0 || $bound >= $quiz->grade)
				return FALSE;
			if ($i > 0 && $bound >= $last_bound)
				return FALSE;
			$last_bound = $bound;
		}
		else {
			if ($bound[$len-1] != '%')
				return FALSE;
			$percent = trim(substr($bound, 0, -1));
			if (!is_numeric($percent))
				return FALSE;
			if ($percent <= 0 || $percent >= 100)
				return FALSE;
			if ($i > 0 && $bound >= $last_bound)
				return FALSE;
			$last_bound = $bound * $quiz->grade / 100.0;
		}
		$bounds[] = $bound;
	}
	$num_feeds = count($feeds);
	$num_bounds = count($bounds);
	if ($num_feeds > 0) {
		if ($num_feeds != $num_bounds + 1)
			return FALSE;
		for ($i = 0; $i < $num_feeds; $i++) {
			if (isset($quiz->feedbacktext[$i]["itemid"]))
				$draftid = $quiz->feedbacktext[$i]["itemid"];
			else
				$draftid = 0;
			$component = "mod_quiz";
			$filearea = "feedback";
			$itemid = null;
			$options = null;
			$text = $feeds[$i];
			$quiz->feedbacktext[$i]["text"] = file_prepare_draft_area(
			  $draftid, $contextid, $component, $filearea, $itemid, $options, $text
			  );
			$quiz->feedbacktext[$i]["format"] = FORMAT_HTML;
			$quiz->feedbacktext[$i]["itemid"] = $draftid;
			if ($i < $num_feeds - 1)
				$quiz->feedbackboundaries[$i] = $bounds[$i];
		}
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$ldb_quiz = intval($data[1]);
	if ($ldb_quiz != 0 && $ldb_quiz != 1)
		return FALSE;
	$RWS_LDB_INFO->attempts = $ldb_quiz;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$ldb_review = intval($data[1]);
	if ($ldb_review != 0 && $ldb_review != 1)
		return FALSE;
	$RWS_LDB_INFO->reviews = $ldb_review;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$RWS_LDB_INFO->password = trim($field); 
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	if ($process_options) {
		if (is_null($quiz->quizpassword) && !is_null($quiz->password))
			$quiz->quizpassword = $quiz->password;
		quiz_process_options($quiz);
	}
	return TRUE;
}
function RWSSaveLDBSettings(&$quiz)
{
	global $RWS_LDB_INFO;
	$RWS_LDB_INFO->put_settings_err = FALSE;
	if ($RWS_LDB_INFO->module_ok) {
		$ok = lockdown_set_settings($quiz->instance, $RWS_LDB_INFO->attempts,
		  $RWS_LDB_INFO->reviews, $RWS_LDB_INFO->password);
		if (!$ok)
			$RWS_LDB_INFO->put_settings_err = TRUE;
	} else if ($RWS_LDB_INFO->block_ok) {
		$update_quiz = FALSE;
		if ($RWS_LDB_INFO->attempts == 1) {
			$ok = lockdown_set_quiz_options($quiz->instance);
			if (!$ok)
				$RWS_LDB_INFO->put_settings_err = TRUE;
			if ($ok) {
				$quiz->name .= get_string("requires_ldb",
				  "block_lockdownbrowser");
				$update_quiz = TRUE;
			}
		} else {
			$record = lockdown_get_quiz_options($quiz->instance);
			if ($record !== FALSE) {
				lockdown_delete_options($quiz->instance);
				$suffix = get_string("requires_ldb", "block_lockdownbrowser");
				$quiz->name = str_replace($suffix, "", $quiz_name);
				$update_quiz = TRUE;
			}
		}
		if ($update_quiz) {
			if (is_null($quiz->quizpassword) && !is_null($quiz->password))
				$quiz->quizpassword = $quiz->password;
			$result = quiz_update_instance($quiz);
			if (!$result || is_string($result))
				$RWS_LDB_INFO->put_settings_err = TRUE;
		}
	} 
}
function RWSImportAttachmentRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $USER;
	if (RWSGetQuestionRecordType($record) != RWS_ATTACHMENT)
		return FALSE;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$file_folder = $field; 
	$file_folder = clean_filename($file_folder);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$file_name = $field; 
	$file_name = clean_filename($file_name);
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$file_data = $field; 
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$context = get_context_instance(CONTEXT_COURSE, $course_id);
	$contextid = $context->id;
	$component = "mod_respondusws";
	$filearea = "upload";
	$itemid = $USER->id;
	$filepath = "/$file_folder/";
	$filename = $file_name;
	$fileinfo = array(
	  "contextid" => $contextid, "component" => $component,
	  "filearea" => $filearea, "itemid" => $itemid,
	  "filepath" => $filepath, "filename" => $filename
	  );
	$course_relpath = "$file_folder/$file_name";
	try {
		$fs = get_file_storage();
		$file_exists = $fs->file_exists(
		  $contextid, $component, $filearea, $itemid, $filepath, $filename
		  );
		if ($file_exists)
			return FALSE;
		if (!$fs->create_file_from_string($fileinfo, $file_data))
			return FALSE;
	} catch (Exception $e) {
		return FALSE;
	}
	return $course_relpath;
}
function RWSImportReservedRecord($course_id, $qcat_id, $record)
{
	if (RWSGetQuestionRecordType($record) != RWS_RESERVED)
		return FALSE;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	return TRUE;
}
function RWSImportShortAnswerRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGetQuestionRecordType($record) != RWS_SHORTANSWER)
		return FALSE;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_SHORTANSWER;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = $data[1];
	else
		$question->defaultgrade = $data[1];
	$count = 8;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$question->penalty = RWSIEEE754ToDouble($field);
	if ($question->penalty < 0 || $question->penalty > 1)
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($question->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$question->penalty = "0.3333333";
			break;
		}
	}
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$options = new stdClass();
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$options->usecase = intval($data[1]);
	if ($options->usecase != 0 && $options->usecase != 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_answers = intval($data[1]);
	if ($num_answers < 1)
		return FALSE;
	$answers = array();
	$max_fraction = -1;
	for ($i = 0; $i < $num_answers; $i++) {
		$answer = new stdClass();
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$answer->answer = trim($field); 
		$answer->answerformat = FORMAT_PLAIN;
		$answer->answer = clean_param($answer->answer, PARAM_RAW);
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$answer->fraction = strval(RWSIEEE754ToDouble($field));
		switch ($answer->fraction) {
			case "1":
			case "0.9":
			case "0.8333333":
			case "0.8":
			case "0.75":
			case "0.7":
			case "0.6666667":
			case "0.6":
			case "0.5":
			case "0.4":
			case "0.3333333":
			case "0.3":
			case "0.25":
			case "0.2":
			case "0.1666667":
			case "0.1428571":
			case "0.125":
			case "0.1111111":
			case "0.1":
			case "0.05":
			case "0":
				break;
			default:
				if (RWSFloatCompare($behavior_version, 2011020100, 2) >= 0)
					$answer->fraction = "0";
				break;
		}
		if (RWSFloatCompare($behavior_version, 2011020100, 2) == -1) {
			switch ($answer->fraction) { 
				case "0.83333":
					$answer->fraction = "0.8333333";
					break;
				case "0.66666":
					$answer->fraction = "0.6666667";
					break;
				case "0.33333":
					$answer->fraction = "0.3333333";
					break;
				case "0.16666":
					$answer->fraction = "0.1666667";
					break;
				case "0.142857":
					$answer->fraction = "0.1428571";
					break;
				case "0.11111":
					$answer->fraction = "0.1111111";
					break;
				default:
					$answer->fraction = "0";
					break;
			}
		}
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$answer->feedback = trim($field); 
		$answer->feedbackformat = FORMAT_HTML;
		$answer->feedback = clean_param($answer->feedback, PARAM_RAW);
		if (strlen($answer->answer) == 0)
			continue;
		$answers[] = $answer;
		if ($answer->fraction > $max_fraction)
			$max_fraction = $answer->fraction;
	}
	if (count($answers) < 1)
		return FALSE;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	$answer_ids = array();
	foreach ($answers as $ans) {
		$ans->question = $question->id;
		$ans->id = $DB->insert_record("question_answers", $ans);
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $ans->id;
		$text = $ans->feedback;
		$ans->feedback = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question_answers", $ans);
		$answer_ids[] = $ans->id;
	}
	$options->question = $question->id;
	$options->answers = implode(",", $answer_ids);
	$options->id = $DB->insert_record("question_shortanswer", $options);
	return $question->id;
}
function RWSImportTrueFalseRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGetQuestionRecordType($record) != RWS_TRUEFALSE)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_TRUEFALSE;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = $data[1];
	else
		$question->defaultgrade = $data[1];
	$count = 8;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$question->penalty = RWSIEEE754ToDouble($field);
	if ($question->penalty != 1) 
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$true = new stdClass();
	$true->answer = get_string("true", "quiz");
	$false = new stdClass();
	$false->answer = get_string("false", "quiz");
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$correct = intval($data[1]);
	if ($correct != 0 && $correct != 1)
		return FALSE;
	$true->fraction = $correct;
	$false->fraction = 1 - $correct;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$true->feedback = trim($field); 
	$true->feedbackformat = FORMAT_HTML;
	$true->feedback = clean_param($true->feedback, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$false->feedback = trim($field); 
	$false->feedbackformat = FORMAT_HTML;
	$false->feedback = clean_param($false->feedback, PARAM_RAW);
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	$true->question = $question->id;
	$true->id = $DB->insert_record("question_answers", $true);
	$component = "question";
	$filearea = "answerfeedback";
	$itemid = $true->id;
	$text = $true->feedback;
	$true->feedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question_answers", $true);
	$false->question = $question->id;
	$false->id = $DB->insert_record("question_answers", $false);
	$component = "question";
	$filearea = "answerfeedback";
	$itemid = $false->id;
	$text = $false->feedback;
	$false->feedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question_answers", $false);
	$options = new stdClass();
	$options->question = $question->id;
	$options->trueanswer = $true->id;
	$options->falseanswer = $false->id;
	$options->id = $DB->insert_record("question_truefalse", $options);
	return $question->id;
}
function RWSImportMultiAnswerRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGetQuestionRecordType($record) != RWS_MULTIANSWER)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_MULTIANSWER;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 8;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$question->penalty = RWSIEEE754ToDouble($field);
	if ($question->penalty < 0 || $question->penalty > 1)
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($question->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$question->penalty = "0.3333333";
			break;
		}
	}
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$children = array();
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = 0;
	else
		$question->defaultgrade = 0;
	$cloze_fields = RWSGetClozeFields($question->questiontext);
	if ($cloze_fields === FALSE)
		return FALSE;
	$child_count = count($cloze_fields);
	for ($i = 0; $i < $child_count; $i++) {
		$child = RWSCreateClozeChild($question, $cloze_fields[$i]);
		if ($child === FALSE)
			return FALSE;
		$children[] = $child;
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
			$question->defaultmark += $child->defaultmark;
		else
			$question->defaultgrade += $child->defaultgrade;
		$positionkey = $i+1;
		$question->questiontext = implode("{#$positionkey}",
		  explode($cloze_fields[$i], $question->questiontext, 2));
	}
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	$child_ids = array();
	foreach ($children as $child) {
		$child->parent = $question->id;
		$child->parent_qtype = $question->qtype;
		$child->id = RWSSaveClozeChild($child, $course_id, $contextid);
		if ($child->id === FALSE) {
			if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
				question_delete_question($question->id);
			else
				delete_question($question->id);
			return FALSE;
		}
		$child_ids[] = $child->id;
	}
	if (count($child_ids) > 0) {
		$options = new stdClass();
		$options->question = $question->id;
		$options->sequence = implode(",", $child_ids);
		$options->id = $DB->insert_record("question_multianswer", $options);
	}
	return $question->id;
}
function RWSCreateClozeChild($question, $field)
{
	global $CFG;
	global $RWS_PCFF_FIELD_NAME;
	$regexp_type = FALSE;
	$qtype_names = get_list_of_plugins("question/type");
	if (count($qtype_names) > 0) {
		foreach ($qtype_names as $qn) {
			if (strcasecmp($qn, RWS_REGEXP) == 0) {
				$regexp_type = TRUE;
				break;
			}
		}
	}
	$regexp_cloze = FALSE;
	$path = "$CFG->dirroot/question/type/multianswer/questiontype.php";
	$data = file_get_contents($path);
	if ($data !== FALSE
	  && strpos($data, "ANSWER_REGEX_ANSWER_TYPE_REGEXP") !== FALSE)
		$regexp_cloze = TRUE;
	$regexp_supported = ($regexp_type && $regexp_cloze);
	$child = new stdClass();
	$child->name = $question->name; 
	$child->category = $question->category;
	$child->questiontext = $field;
	$child->questiontextformat = $question->questiontextformat;
	$child->questiontext = clean_param($child->questiontext, PARAM_RAW);
	$child->answer = array();
	$child->answerformat = array();
	$child->fraction = array();
	$child->feedback = array();
	$child->feedbackformat = array();
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$child->defaultmark = 1;
	else
		$child->defaultgrade = 1;
	$start = 1;
	$offset = strpos(substr($field, $start), ":");
	if ($offset === FALSE)
		return FALSE;
	if ($offset > 0) {
		$subfield = trim(substr($field, $start, $offset));
		if (strlen($subfield) > 0 && is_numeric($subfield)) {
			if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
				$child->defaultmark = floatval($subfield);
			else
				$child->defaultgrade = floatval($subfield);
		}
	}
	$start += $offset;
	$subfield = substr($field, $start);
	if (strncmp($subfield, ":NUMERICAL:", 11) == 0
	  || strncmp($subfield, ":NM:", 4) == 0) {
        $child->qtype = RWS_NUMERICAL;
		$child->tolerance = array();
        $child->multiplier = array();
        $child->units = array();
		$child->instructions = "";
		$child->instructionsformat = FORMAT_HTML;
	} else if (strncmp($subfield, ":SHORTANSWER:", 13) == 0
	  || strncmp($subfield, ":SA:", 4) == 0
	  || strncmp($subfield, ":MW:", 4) == 0) {
        $child->qtype = RWS_SHORTANSWER;
		$child->usecase = 0;
	} else if (strncmp($subfield, ":SHORTANSWER_C:", 15) == 0
	  || strncmp($subfield, ":SAC:", 5) == 0
	  || strncmp($subfield, ":MWC:", 5) == 0) {
        $child->qtype = RWS_SHORTANSWER;
		$child->usecase = 1;
	} else if (strncmp($subfield, ":MULTICHOICE:", 13) == 0
	  || strncmp($subfield, ":MC:", 4) == 0) {
        $child->qtype = RWS_MULTICHOICE;
		$child->single = 1;
		$child->answernumbering = 0;
		$child->shuffleanswers = 1;
		$child->correctfeedback = "";
		$child->correctfeedbackformat = FORMAT_HTML;
		$child->partiallycorrectfeedback = "";
		if (strlen($RWS_PCFF_FIELD_NAME) > 0)
			$child->$RWS_PCFF_FIELD_NAME = FORMAT_HTML;
		$child->incorrectfeedback = "";
		$child->incorrectfeedbackformat = FORMAT_HTML;
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
			$child->shownumcorrect = 0;
		$child->layout = 0;
	} else if (strncmp($subfield, ":MULTICHOICE_V:", 15) == 0
	  || strncmp($subfield, ":MCV:", 5) == 0) {
        $child->qtype = RWS_MULTICHOICE;
		$child->single = 1;
		$child->answernumbering = 0;
		$child->shuffleanswers = 1;
		$child->correctfeedback = "";
		$child->correctfeedbackformat = FORMAT_HTML;
		$child->partiallycorrectfeedback = "";
		if (strlen($RWS_PCFF_FIELD_NAME) > 0)
			$child->$RWS_PCFF_FIELD_NAME = FORMAT_HTML;
		$child->incorrectfeedback = "";
		$child->incorrectfeedbackformat = FORMAT_HTML;
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
			$child->shownumcorrect = 0;
		$child->layout = 1;
	} else if (strncmp($subfield, ":MULTICHOICE_H:", 15) == 0
	  || strncmp($subfield, ":MCH:", 5) == 0) {
        $child->qtype = RWS_MULTICHOICE;
		$child->single = 1;
		$child->answernumbering = 0;
		$child->shuffleanswers = 1;
		$child->correctfeedback = "";
		$child->correctfeedbackformat = FORMAT_HTML;
		$child->partiallycorrectfeedback = "";
		if (strlen($RWS_PCFF_FIELD_NAME) > 0)
			$child->$RWS_PCFF_FIELD_NAME = FORMAT_HTML;
		$child->incorrectfeedback = "";
		$child->incorrectfeedbackformat = FORMAT_HTML;
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
			$child->shownumcorrect = 0;
		$child->layout = 2;
	} else if ($regexp_supported
	  && strncmp($subfield, ":REGEXP:", 8) == 0) {
        $child->qtype = RWS_REGEXP;
        $child->usehint = 0;
	} else {
		return FALSE;
	}
	$start++;
	$offset = strpos(substr($field, $start), ":");
	$start += $offset;
	$start++;
	$field_len = strlen($field);
	while ($start < $field_len) {
		if ($field[$start] == '}') { 
			break;
		}
		if ($field[$start] == '~') { 
			$start++;
		}
		$fraction = "0";
		if ($field[$start] == '=') { 
			$fraction = "1";
			$start++;
		}
		if ($field[$start] == '%') { 
			$start++;
			$percent = "";
			while ($start < $field_len) {
				if ($field[$start] == '%')
					break;
				$percent .= $field[$start];
				$start++;
			}
			$percent = trim($percent);
			if (strlen($percent) == 0 || !ctype_digit($percent))
				return FALSE;
			$fraction = .01 * $percent;
			$start++;
		}
		$answer = "";
		if ($child->qtype == RWS_NUMERICAL) {
			$tolerance = "";
			$found = FALSE;
			while ($start < $field_len) {
				if ($field[$start] == '#'
				  || $field[$start] == '~'
				  || $field[$start] == '}') {
					break;
				} else if ($field[$start] == ':') {
					$found = TRUE;
					$start++;
					continue;
				}
				if ($found)
					$tolerance .= $field[$start];
				else
					$answer .= $field[$start];
				$start++;
			}
			$answer = trim($answer);
			if (strlen($answer) == 0)
				return FALSE;
			if (($answer != strval(floatval($answer))) && $answer != "*")
				return FALSE;
			$answer = clean_param($answer, PARAM_RAW);
			$tolerance = trim($tolerance);
			if (strlen($tolerance) == 0
			  || ($tolerance != strval(floatval($tolerance)))
			  || $answer == "*")
				$tolerance = 0;
		} else { 
			$in_tag = FALSE;
			while ($start < $field_len) {
				if ($field[$start] == '<')
					$in_tag = TRUE;
				else if ($field[$start] == '>')
					$in_tag = FALSE;
				else if (!$in_tag &&
				  ($field[$start] == '#'
					|| $field[$start] == '~'
					|| $field[$start] == '}')) {
					$start--;
					$escaped = ($field[$start] == '\\');
					$start++;
					if (!$escaped)
						break;
				}
				$answer .= $field[$start];
				$start++;
			}
			$answer = trim($answer);
			if (strlen($answer) == 0)
				return FALSE;
			$answer = str_replace("\#", "#", $answer);
			$answer = str_replace("\}", "}", $answer);
			$answer = str_replace("\~", "~", $answer);
			$answer = clean_param($answer, PARAM_RAW);
		}
		$feedback = "";
		if ($field[$start] == '#') { 
			$start++;
			$feedback = "";
			$in_tag = FALSE;
			while ($start < $field_len) {
				if ($field[$start] == '<')
					$in_tag = TRUE;
				else if ($field[$start] == '>')
					$in_tag = FALSE;
				else if (!$in_tag &&
				  ($field[$start] == '~'
					|| $field[$start] == '}')) {
					$start--;
					$escaped = ($field[$start] == '\\');
					$start++;
					if (!$escaped)
						break;
				}
				$feedback .= $field[$start];
				$start++;
			}
			$feedback = trim($feedback);
			$feedback = str_replace("\#", "#", $feedback);
			$feedback = str_replace("\}", "}", $feedback);
			$feedback = str_replace("\~", "~", $feedback);
			$feedback = clean_param($feedback, PARAM_RAW);
		}
		$child->answer[] = $answer;
		if ($child->qtype == RWS_NUMERICAL
		  || $child->qtype == RWS_SHORTANSWER
		  || $child->qtype == RWS_REGEXP)
			$child->answerformat[] = FORMAT_PLAIN;
		else
			$child->answerformat[] = FORMAT_HTML;
		$child->fraction[] = $fraction;
		$child->feedback[] = $feedback;
		$child->feedbackformat[] = FORMAT_HTML;
		if ($child->qtype == RWS_NUMERICAL)
			$child->tolerance[] = $tolerance;
	}
	$num_answers = count($child->answer);
	if ($num_answers == 0)
		return FALSE;
	if (count($child->fraction) != $num_answers)
		return FALSE;
	if (count($child->feedback) != $num_answers)
		return FALSE;
	if ($child->qtype == RWS_NUMERICAL && count($child->tolerance) != $num_answers)
		return FALSE;
	return $child;
}
function RWSGetClozeFields($question_text)
{
	$pos = 0;
	$len = strlen($question_text);
	$in_tag = FALSE;
	$in_field = FALSE;
	$fields = array();
	while ($pos < $len) {
		if ($question_text[$pos] == '<')
			$in_tag = TRUE;
		else if ($question_text[$pos] == '>')
			$in_tag = FALSE;
		else if (!$in_field && !$in_tag && $question_text[$pos] == '{') {
			$escaped = FALSE;
			if ($pos > 0) {
				$pos--;
				$escaped = ($question_text[$pos] == '\\');
				$pos++;
			}
			if (!$escaped) {
				$field = "";
				$in_field = TRUE;
			}
		}
		else if ($in_field && !$in_tag && $question_text[$pos] == '}') {
			$pos--;
			$escaped = ($question_text[$pos] == '\\');
			$pos++;
			if (!$escaped) {
				$field .= $question_text[$pos];
				$fields[] = $field;
				$in_field = FALSE;
			}
		}		
		if ($in_field)
			$field .= $question_text[$pos];
		$pos++;
	}
	return $fields;
}
function RWSSaveClozeChild($child, $course_id, $contextid)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWS_PCFF_FIELD_NAME;
	$child->hidden = 0;
	$child->length = 1;
	$child->stamp = make_unique_id_code();
	$child->createdby = $USER->id;
	$child->modifiedby = $USER->id;
	$child->penalty = 0;
	$child->generalfeedback = "";
	$child->generalfeedbackformat = FORMAT_HTML;
	$child->timecreated = time();
	$child->timemodified = time();
	if ($child->qtype == RWS_NUMERICAL) {
		$child->id = $DB->insert_record("question", $child);
		$component = "question";
		$filearea = "questiontext";
		$itemid = $child->id;
		$text = $child->questiontext;
		$child->questiontext = RWSProcessAttachments($child->parent_qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question", $child);
		$hash = question_hash($child);
		$DB->set_field("question", "version", $hash,
		  array("id" => $child->id));
		$num_answers = count($child->answer);
		for ($i = 0; $i < $num_answers; $i++) {
			$ans = new stdClass();
			$ans->answer = $child->answer[$i]; 
			$ans->answerformat = $child->answerformat[$i];
			$ans->fraction = $child->fraction[$i];
			$ans->feedback = $child->feedback[$i];
			$ans->feedbackformat = $child->feedbackformat[$i];
			$ans->question = $child->id;
			$ans->id = $DB->insert_record("question_answers", $ans);
			$component = "question";
			$filearea = "answerfeedback";
			$itemid = $ans->id;
			$text = $ans->feedback;
			$ans->feedback = RWSProcessAttachments($child->parent_qtype,
			  $course_id, $contextid, $component, $filearea, $itemid, $text
			  );
			$DB->update_record("question_answers", $ans);
			$options = new stdClass();
			$options->question = $child->id;
			$options->answer = $ans->id;
			$options->tolerance = $child->tolerance[$i]; 
			$options->id = $DB->insert_record("question_numerical", $options);
		}
	} else if ($child->qtype == RWS_SHORTANSWER) {
		$child->id = $DB->insert_record("question", $child);
		$component = "question";
		$filearea = "questiontext";
		$itemid = $child->id;
		$text = $child->questiontext;
		$child->questiontext = RWSProcessAttachments($child->parent_qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question", $child);
		$hash = question_hash($child);
		$DB->set_field("question", "version", $hash,
		  array("id" => $child->id));
		$answer_ids = array();
		$num_answers = count($child->answer);
		for ($i = 0; $i < $num_answers; $i++) {
			$ans = new stdClass();
			$ans->answer = $child->answer[$i];
			$ans->answerformat = $child->answerformat[$i];
			$ans->fraction = $child->fraction[$i];
			$ans->feedback = $child->feedback[$i];
			$ans->feedbackformat = $child->feedbackformat[$i];
			$ans->question = $child->id;
			$ans->id = $DB->insert_record("question_answers", $ans);
			$component = "question";
			$filearea = "answerfeedback";
			$itemid = $ans->id;
			$text = $ans->feedback;
			$ans->feedback = RWSProcessAttachments($child->parent_qtype,
			  $course_id, $contextid, $component, $filearea, $itemid, $text
			  );
			$DB->update_record("question_answers", $ans);
			$answer_ids[] = $ans->id;
		}
		$options = new stdClass();
		$options->usecase = $child->usecase;
		$options->question = $child->id;
		$options->answers = implode(",", $answer_ids);
		$options->id = $DB->insert_record("question_shortanswer", $options);
	} else if ($child->qtype == RWS_MULTICHOICE) {
		$child->id = $DB->insert_record("question", $child);
		$component = "question";
		$filearea = "questiontext";
		$itemid = $child->id;
		$text = $child->questiontext;
		$child->questiontext = RWSProcessAttachments($child->parent_qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question", $child);
		$hash = question_hash($child);
		$DB->set_field("question", "version", $hash,
		  array("id" => $child->id));
		$answer_ids = array();
		$num_answers = count($child->answer);
		for ($i = 0; $i < $num_answers; $i++) {
			$ans = new stdClass();
			$ans->answer = $child->answer[$i];
			$ans->answerformat = $child->answerformat[$i];
			$ans->fraction = $child->fraction[$i];
			$ans->feedback = $child->feedback[$i];
			$ans->feedbackformat = $child->feedbackformat[$i];
			$ans->question = $child->id;
			$ans->id = $DB->insert_record("question_answers", $ans);
			$component = "question";
			$filearea = "answer";
			$itemid = $ans->id;
			$text = $ans->answer;
			$ans->answer = RWSProcessAttachments($child->parent_qtype,
			  $course_id, $contextid, $component, $filearea, $itemid, $text
			  );
			$component = "question";
			$filearea = "answerfeedback";
			$itemid = $ans->id;
			$text = $ans->feedback;
			$ans->feedback = RWSProcessAttachments($child->parent_qtype,
			  $course_id, $contextid, $component, $filearea, $itemid, $text
			  );
			$DB->update_record("question_answers", $ans);
			$answer_ids[] = $ans->id;
		}
		$options = new stdClass();
		$options->question = $child->id;
		$options->answers = implode(",", $answer_ids);
		$options->single = $child->single;
		$options->answernumbering = $child->answernumbering;
		$options->shuffleanswers = $child->shuffleanswers;
		$options->correctfeedback = $child->correctfeedback;
		$options->partiallycorrectfeedback = $child->partiallycorrectfeedback;
		$options->incorrectfeedback = $child->incorrectfeedback;
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
			$options->shownumcorrect = $child->shownumcorrect;
		$options->layout = $child->layout;
		$options->id = $DB->insert_record("question_multichoice", $options);
	} else if ($child->qtype == RWS_REGEXP) {
		$child->id = $DB->insert_record("question", $child);
		$hash = question_hash($child);
		$component = "question";
		$filearea = "questiontext";
		$itemid = $child->id;
		$text = $child->questiontext;
		$child->questiontext = RWSProcessAttachments($child->parent_qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question", $child);
		$DB->set_field("question", "version", $hash,
		  array("id" => $child->id));
		$answer_ids = array();
		$num_answers = count($child->answer);
		for ($i = 0; $i < $num_answers; $i++) {
			$ans = new stdClass();
			$ans->answer = $child->answer[$i];
			$ans->answerformat = $child->answerformat[$i];
			$ans->fraction = $child->fraction[$i];
			$ans->feedback = $child->feedback[$i];
			$ans->feedbackformat = $child->feedbackformat[$i];
			$ans->question = $child->id;
			$ans->id = $DB->insert_record("question_answers", $ans);
			$component = "question";
			$filearea = "answerfeedback";
			$itemid = $ans->id;
			$text = $ans->feedback;
			$ans->feedback = RWSProcessAttachments($child->parent_qtype,
			  $course_id, $contextid, $component, $filearea, $itemid, $text
			  );
			$DB->update_record("question_answers", $ans);
			$answer_ids[] = $ans->id;
		}
		$options = new stdClass();
		$options->question = $child->id;
		$options->answers = implode(",", $answer_ids);
		$options->id = $DB->insert_record("question_regexp", $options);
	} else {
		return FALSE;
	}
	return $child->id;
}
function RWSImportCalculatedRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWS_PCFF_FIELD_NAME;
	if (RWSGetQuestionRecordType($record) != RWS_CALCULATED)
		return FALSE;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_CALCULATED;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = $data[1];
	else
		$question->defaultgrade = $data[1];
	$count = 8;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$question->penalty = RWSIEEE754ToDouble($field);
	if ($question->penalty < 0 || $question->penalty > 1)
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($question->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$question->penalty = "0.3333333";
			break;
		}
	}
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_answers = intval($data[1]);
	if ($num_answers != 1)
		return FALSE;
	$answers = array();
	$total_fraction = 0;
	for ($i = 0; $i < $num_answers; $i++) {
		$ans = new stdClass();
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$ans->formula = trim($field); 
		if (strlen($ans->formula) == 0)
			return FALSE;
		if (!RWSCheckFormulaSyntax($ans->formula))
			return FALSE;
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$ans->fraction = strval(RWSIEEE754ToDouble($field));
		switch ($ans->fraction) {
			case "1":
			case "0.9":
			case "0.8333333":
			case "0.8":
			case "0.75":
			case "0.7":
			case "0.6666667":
			case "0.6":
			case "0.5":
			case "0.4":
			case "0.3333333":
			case "0.3":
			case "0.25":
			case "0.2":
			case "0.1666667":
			case "0.1428571":
			case "0.125":
			case "0.1111111":
			case "0.1":
			case "0.05":
			case "0":
				break;
			default:
				if (RWSFloatCompare($behavior_version, 2011020100, 2) >= 0)
					$answer->fraction = "0";
				break;
		}
		if (RWSFloatCompare($behavior_version, 2011020100, 2) == -1) {
			switch ($answer->fraction) { 
				case "0.83333":
					$answer->fraction = "0.8333333";
					break;
				case "0.66666":
					$answer->fraction = "0.6666667";
					break;
				case "0.33333":
					$answer->fraction = "0.3333333";
					break;
				case "0.16666":
					$answer->fraction = "0.1666667";
					break;
				case "0.142857":
					$answer->fraction = "0.1428571";
					break;
				case "0.11111":
					$answer->fraction = "0.1111111";
					break;
				default:
					$answer->fraction = "0";
					break;
			}
		}
		if ($ans->fraction != "1")
			return FALSE;
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$ans->feedback = trim($field); 
		$ans->feedbackformat = FORMAT_HTML;
		$ans->feedback = clean_param($ans->feedback, PARAM_RAW);
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$ans->tolerance = RWSIEEE754ToDouble($field);
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$ans->tolerancetype = intval($data[1]);
		switch ($ans->tolerancetype) {
		case 1: 
		case 2: 
		case 3: 
			break;
		default:
			return FALSE;
		}
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$ans->correctanswerlength = intval($data[1]);
		if ($ans->correctanswerlength < 0 || $ans->correctanswerlength > 9)
			return FALSE;
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$ans->correctanswerformat = intval($data[1]);
		switch ($ans->correctanswerformat) {
		case 1: 
		case 2: 
			break;
		default:
			return FALSE;
		}
		$answers[] = $ans;
		$total_fraction += $ans->fraction;
	}
	if (count($answers) != 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_units = intval($data[1]);
	if ($num_units < 0 || $num_units > 1)
		return FALSE;
	$units = array();
	$found_base_unit = FALSE;
	for ($i = 0; $i < $num_units; $i++) {
		$unit = new stdClass();
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$unit->name = trim($field); 
		if (strlen($unit->name) == 0)
			return FALSE;
		$unit->name = clean_param($unit->name, PARAM_NOTAGS);
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$unit->multiplier = RWSIEEE754ToDouble($field);
		if (RWSFloatCompare($unit->multiplier, 1, 1) == 0)
			$found_base_unit = TRUE;
		else 
			return FALSE;
		$units[] = $unit;
	}
	if (count($units) > 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_dsets = intval($data[1]);
	if ($num_dsets < 1)
		return FALSE;
	$datasets = array();
	for ($i = 0; $i < $num_dsets; $i++) {
		$dset = new stdClass();
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$dset->name = trim($field); 
		if (strlen($dset->name) == 0)
			return FALSE;
		$dset->name = clean_param($dset->name, PARAM_NOTAGS);
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$dset->distribution = trim($field); 
		switch ($dset->distribution) {
		case "uniform":
		case "loguniform":
			break;
		default:
			return FALSE;
		}
		if ($dset->distribution != "uniform")
			return FALSE;
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$dset->min = RWSIEEE754ToDouble($field);
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$dset->max = RWSIEEE754ToDouble($field);
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$dset->precision = intval($data[1]);
		if ($dset->precision < 0 || $dset->precision > 10)
			return FALSE;
		if (RWSFloatCompare($dset->max, $dset->min, $dset->precision) < 0)
			return FALSE;
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$dset->type = intval($data[1]);
		if ($dset->type != 1)
			return FALSE;
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$dset->status = intval($data[1]);
		if ($dset->status != 0 && $dset->status != 1)
			return FALSE;
		$count = 1;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$data = unpack("C", $field);
		$dset->itemcount = intval($data[1]);
		if ($dset->itemcount < 1)
			return FALSE;
		$dset->items = array();
		$map = array_fill(1, $dset->itemcount, 0);
		for ($j = 0; $j < $dset->itemcount; $j++) {
			$item = new stdClass();
			$count = 1;
			if ($size < $count)
				return FALSE;
			$field = substr($record, $pos, $count);
			$pos += $count;
			$size -= $count;
			$data = unpack("C", $field);
			$item->itemnumber = intval($data[1]);
			if ($item->itemnumber < 1 || $item->itemnumber > $dset->itemcount)
				return FALSE;
			if ($map[$item->itemnumber] == 1) 
				return FALSE;
			$map[$item->itemnumber] = 1;
			$count = 8;
			if ($size < $count)
				return FALSE;
			$field = substr($record, $pos, $count);
			$pos += $count;
			$size -= $count;
			$item->value = RWSIEEE754ToDouble($field);
			$dset->items[] = $item;
		}
		if (array_sum($map) != $dset->itemcount)
			return FALSE;
		$datasets[] = $dset;
	}
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	$options = new stdClass();
	$options->question = $question->id;
    $options->synchronize = 0;
    $options->single = 0;
    $options->answernumbering = "abc";
    $options->shuffleanswers = 0;
    $options->correctfeedback = "";
    $options->correctfeedbackformat = FORMAT_HTML;
    $options->partiallycorrectfeedback = "";
    if (strlen($RWS_PCFF_FIELD_NAME) > 0)
		$options->$RWS_PCFF_FIELD_NAME = FORMAT_HTML;
    $options->incorrectfeedback = "";
    $options->incorrectfeedbackformat = FORMAT_HTML;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$options->shownumcorrect = 0;
	$options->id = $DB->insert_record("question_calculated_options", $options);
	foreach ($answers as $a) {
		$ans = new stdClass();
		$ans->answer = $a->formula;
		$ans->fraction = $a->fraction;
		$ans->feedback = $a->feedback;
		$ans->feedbackformat = $a->feedbackformat;
		$ans->question = $question->id;
		$ans->id = $DB->insert_record("question_answers", $ans);
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $ans->id;
		$text = $ans->feedback;
		$ans->feedback = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question_answers", $ans);
		$opt = new stdClass();
		$opt->tolerance = $a->tolerance;
		$opt->tolerancetype = $a->tolerancetype;
		$opt->correctanswerlength = $a->correctanswerlength;
		$opt->correctanswerformat = $a->correctanswerformat;
		$opt->question = $question->id;
		$opt->answer = $ans->id;
		$opt->id = $DB->insert_record("question_calculated", $opt);
	}
	foreach ($units as $u) {
		$unit = new stdClass();
		$unit->unit = $u->name;
		$unit->multiplier = $u->multiplier;
		$unit->question = $question->id;
		$unit->id = $DB->insert_record("question_numerical_units", $unit);
	}
	$opt = new stdClass();
    $opt->question = $question->id;
    $opt->unitpenalty = 0.1;
    if (count($units) > 0) {
		$opt->unitgradingtype = RWS_UNIT_GRADED;
        $opt->showunits = RWS_UNIT_INPUT;
	}
    else {
		$opt->unitgradingtype = RWS_UNIT_OPTIONAL;
        $opt->showunits = RWS_UNIT_NONE;
	}
    $opt->unitsleft = 0;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) < 0) { 
		$opt->instructions = "";
		$opt->instructionsformat = FORMAT_HTML;
	}
	$opt->id = $DB->insert_record("question_numerical_options", $opt);
	foreach ($datasets as $dset) {
		$def = new stdClass();
		$def->name = $dset->name;
		$def->options =
		  "$dset->distribution:$dset->min:$dset->max:$dset->precision";
		$def->itemcount = $dset->itemcount;
		$def->type = $dset->type;
		if ($dset->status == 0)
			$def->category = 0; 
		else 
			$def->category = $question->category;
		$def->id = $DB->insert_record("question_dataset_definitions", $def);
		$qds = new stdClass();
		$qds->question = $question->id;
		$qds->datasetdefinition = $def->id;
		$qds->id = $DB->insert_record("question_datasets", $qds);
		foreach ($dset->items as $dsi) {
			$item = new stdClass();
			$item->itemnumber = $dsi->itemnumber;
			$item->value = $dsi->value;
			$item->definition = $def->id;
			$item->id = $DB->insert_record("question_dataset_items", $item);
		}
	}
	return $question->id;
}
function RWSCheckFormulaSyntax($formula)
{
    while (ereg('\\{[[:alpha:]][^>} <{"\']*\\}', $formula, $regs)) {
        $formula = str_replace($regs[0], '1', $formula);
    }
    $formula = strtolower(str_replace(' ', '', $formula));
	$safeoperatorchar = '-+/*%>:^~<?=&|!';
	$operatorornumber = "[$safeoperatorchar.0-9eE]";
    while (ereg("(^|[$safeoperatorchar,(])([a-z0-9_]*)\\(($operatorornumber+(,$operatorornumber+((,$operatorornumber+)+)?)?)?\\)",
            $formula, $regs)) {
		switch ($regs[2]) {
            case '':
                if ((isset($regs[4]) && $regs[4]) || strlen($regs[3])==0) {
                    return FALSE; 
                }
                break;
            case 'pi':
                if ($regs[3]) {
                    return FALSE; 
                }
                break;
            case 'abs': case 'acos': case 'acosh': case 'asin': case 'asinh':
            case 'atan': case 'atanh': case 'bindec': case 'ceil': case 'cos':
            case 'cosh': case 'decbin': case 'decoct': case 'deg2rad':
            case 'exp': case 'expm1': case 'floor': case 'is_finite':
            case 'is_infinite': case 'is_nan': case 'log10': case 'log1p':
            case 'octdec': case 'rad2deg': case 'sin': case 'sinh': case 'sqrt':
            case 'tan': case 'tanh':
                if (!empty($regs[4]) || empty($regs[3])) {
                    return FALSE; 
                }
                break;
            case 'log': case 'round':
                if (!empty($regs[5]) || empty($regs[3])) {
                    return FALSE; 
                }
                break;
            case 'atan2': case 'fmod': case 'pow':
                if (!empty($regs[5]) || empty($regs[4])) {
                    return FALSE; 
                }
                break;
            case 'min': case 'max':
                if (empty($regs[4])) {
                    return FALSE; 
                }
                break;
            default:
                return FALSE; 
        }
        if ($regs[1]) {
            $formula = str_replace($regs[0], $regs[1] . '1', $formula);
        } else {
            $formula = ereg_replace("^$regs[2]\\([^)]*\\)", '1', $formula);
        }
    }
	if (ereg("[^$safeoperatorchar.0-9eE]+", $formula, $regs)) {
		return FALSE; 
    } else {
        return TRUE; 
    }
}
function RWSImportMultipleChoiceRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWS_PCFF_FIELD_NAME;
	if (RWSGetQuestionRecordType($record) != RWS_MULTICHOICE)
		return FALSE;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_MULTICHOICE;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = $data[1];
	else
		$question->defaultgrade = $data[1];
	$count = 8;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$question->penalty = RWSIEEE754ToDouble($field);
	if ($question->penalty < 0 || $question->penalty > 1)
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($question->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$question->penalty = "0.3333333";
			break;
		}
	}
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$options = new stdClass();
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$options->single = intval($data[1]);
	if ($options->single != 0 && $options->single != 1)
		return FALSE;
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$flag = intval($data[1]);
	if ($flag != 0 && $flag != 1)
		return FALSE;
	$options->shuffleanswers = (bool)$flag;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$options->answernumbering = trim($field); 
	switch ($options->answernumbering) {
	case "abc":
	case "ABCD":
	case "123":
	case "none":
		break;
	default:
		return FALSE;
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_answers = intval($data[1]);
	if ($num_answers < 2)
		return FALSE;
	$answers = array();
	$total_fraction = 0;
	$max_fraction = -1;
	for ($i = 0; $i < $num_answers; $i++) {
		$answer = new stdClass();
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$answer->answer = trim($field); 
		$answer->answerformat = FORMAT_HTML;
		$answer->answer = clean_param($answer->answer, PARAM_RAW);
		$count = 8;
		if ($size < $count)
			return FALSE;
		$field = substr($record, $pos, $count);
		$pos += $count;
		$size -= $count;
		$answer->fraction = strval(RWSIEEE754ToDouble($field));
		switch ($answer->fraction) {
			case "1":
			case "0.9":
			case "0.8333333":
			case "0.8":
			case "0.75":
			case "0.7":
			case "0.6666667":
			case "0.6":
			case "0.5":
			case "0.4":
			case "0.3333333":
			case "0.3":
			case "0.25":
			case "0.2":
			case "0.1666667":
			case "0.1428571":
			case "0.125":
			case "0.1111111":
			case "0.1":
			case "0.05":
			case "0":
			case "-0.05":
			case "-0.1":
			case "-0.1111111":
			case "-0.125":
			case "-0.1428571":
			case "-0.1666667":
			case "-0.2":
			case "-0.25":
			case "-0.3":
			case "-0.3333333":
			case "-0.4":
			case "-0.5":
			case "-0.6":
			case "-0.6666667":
			case "-0.7":
			case "-0.75":
			case "-0.8":
			case "-0.8333333":
			case "-0.9":
			case "-1":
				break;
			default:
				if (RWSFloatCompare($behavior_version, 2011020100, 2) >= 0)
					$answer->fraction = "0";
				break;
		}
		if (RWSFloatCompare($behavior_version, 2011020100, 2) == -1) {
			switch ($answer->fraction) { 
				case "0.83333":
					$answer->fraction = "0.8333333";
					break;
				case "0.66666":
					$answer->fraction = "0.6666667";
					break;
				case "0.33333":
					$answer->fraction = "0.3333333";
					break;
				case "0.16666":
					$answer->fraction = "0.1666667";
					break;
				case "0.142857":
					$answer->fraction = "0.1428571";
					break;
				case "0.11111":
					$answer->fraction = "0.1111111";
					break;
				case "-0.11111":
					$answer->fraction = "-0.1111111";
					break;
				case "-0.142857":
					$answer->fraction = "-0.1428571";
					break;
				case "-0.16666":
					$answer->fraction = "-0.1666667";
					break;
				case "-0.33333":
					$answer->fraction = "-0.3333333";
					break;
				case "-0.66666":
					$answer->fraction = "-0.6666667";
					break;
				case "-0.83333":
					$answer->fraction = "-0.8333333";
					break;
				default:
					$answer->fraction = "0";
					break;
			}
		}
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$answer->feedback = trim($field); 
		$answer->feedbackformat = FORMAT_HTML;
		$answer->feedback = clean_param($answer->feedback, PARAM_RAW);
		if (strlen($answer->answer) == 0)
			continue;
		$answers[] = $answer;
		if ($answer->fraction > 0)
			$total_fraction += $answer->fraction;
		if ($answer->fraction > $max_fraction)
			$max_fraction = $answer->fraction;
	}
	if (count($answers) < 2)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$options->correctfeedback = trim($field); 
	$options->correctfeedbackformat = FORMAT_HTML;
	$options->correctfeedback = clean_param($options->correctfeedback, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$options->partiallycorrectfeedback = trim($field); 
	if (strlen($RWS_PCFF_FIELD_NAME) > 0)
		$options->$RWS_PCFF_FIELD_NAME = FORMAT_HTML;
	$options->partiallycorrectfeedback = clean_param($options->partiallycorrectfeedback, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$options->incorrectfeedback = trim($field); 
	$options->incorrectfeedbackformat = FORMAT_HTML;
	$options->incorrectfeedback = clean_param($options->incorrectfeedback, PARAM_RAW);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$options->shownumcorrect = 0;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	$answer_ids = array();
	foreach ($answers as $ans) {
		$ans->question = $question->id;
		$ans->id = $DB->insert_record("question_answers", $ans);
		$component = "question";
		$filearea = "answer";
		$itemid = $ans->id;
		$text = $ans->answer;
		$ans->answer = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $ans->id;
		$text = $ans->feedback;
		$ans->feedback = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question_answers", $ans);
		$answer_ids[] = $ans->id;
	}
	$options->question = $question->id;
	$options->answers = implode(",", $answer_ids);
	$options->id = $DB->insert_record("question_multichoice", $options);
	$component = "qtype_multichoice";
	$filearea = "correctfeedback";
	$itemid = $question->id;
	$text = $options->correctfeedback;
	$options->correctfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "qtype_multichoice";
	$filearea = "partiallycorrectfeedback";
	$itemid = $question->id;
	$text = $options->partiallycorrectfeedback;
	$options->partiallycorrectfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "qtype_multichoice";
	$filearea = "incorrectfeedback";
	$itemid = $question->id;
	$text = $options->incorrectfeedback;
	$options->incorrectfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question_multichoice", $options);
	return $question->id;
}
function RWSImportMatchingRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWS_PCFF_FIELD_NAME;
	if (RWSGetQuestionRecordType($record) != RWS_MATCH)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_MATCH;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = $data[1];
	else
		$question->defaultgrade = $data[1];
	$count = 8;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$question->penalty = RWSIEEE754ToDouble($field);
	if ($question->penalty < 0 || $question->penalty > 1)
		return FALSE;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($question->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$question->penalty = "0.3333333";
			break;
		}
	}
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$options = new stdClass();
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$flag = intval($data[1]);
	if ($flag != 0 && $flag != 1)
		return FALSE;
	$options->shuffleanswers = (bool)$flag;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$options->correctfeedback = "";
		$options->correctfeedbackformat = FORMAT_HTML;
		$options->partiallycorrectfeedback = "";
		if (strlen($RWS_PCFF_FIELD_NAME) > 0)
			$options->$RWS_PCFF_FIELD_NAME = FORMAT_HTML;
		$options->incorrectfeedback = "";
		$options->incorrectfeedbackformat = FORMAT_HTML;
		$options->shownumcorrect = 0;
	}
	$count = 1;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("C", $field);
	$num_pairs = intval($data[1]);
	if ($num_pairs < 3)
		return FALSE;
	$pairs = array();
	$subq_count = 0;
	for ($i = 0; $i < $num_pairs; $i++) {
		$subquestion = new stdClass();
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$subquestion->questiontext = trim($field); 
		$subquestion->questiontextformat = FORMAT_HTML;
		$subquestion->questiontext = clean_param($subquestion->questiontext, PARAM_RAW);
		if ($size < 1)
			return FALSE;
		$count = strpos(substr($record, $pos), "\0");
		if ($count === FALSE)
			return FALSE;
		if ($count > 0)
			$field = substr($record, $pos, $count);
		else
			$field = "";
		$count++; 
		$pos += $count;
		$size -= $count;
		$subquestion->answertext = trim($field); 
		$subquestion->answertext = clean_param($subquestion->answertext, PARAM_TEXT);
		if (strlen($subquestion->answertext) == 0)
			continue;
		if (strlen($subquestion->questiontext) != 0)
			$subq_count++;
		$pairs[] = $subquestion;
	}
	if ($subq_count < 2 || count($pairs) < 3)
		return FALSE;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	$pair_ids = array();
	foreach ($pairs as $pair) {
        $pair->code = rand(1, 999999999);
        while ($DB->record_exists("question_match_sub", array(
		  "code" => $pair->code, "question" => $question->id
		  )) === TRUE) {
            $pair->code = rand(1, 999999999);
        }
		$pair->question = $question->id;
		$pair->id = $DB->insert_record("question_match_sub", $pair);
		$component = "qtype_match";
		$filearea = "subquestion";
		$itemid = $pair->id;
		$text = $pair->questiontext;
		$pair->questiontext = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("question_match_sub", $pair);
		$pair_ids[] = $pair->id;
	}
	$options->question = $question->id;
	$options->subquestions = implode(",", $pair_ids);
	$options->id = $DB->insert_record("question_match", $options);
	return $question->id;
}
function RWSImportDescriptionRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGetQuestionRecordType($record) != RWS_DESCRIPTION)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_DESCRIPTION;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 0;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = 0;
	else
		$question->defaultgrade = 0;
	$question->penalty = 0;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	return $question->id;
}
function RWSImportEssayRecord($course_id, $qcat_id, $record)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGetQuestionRecordType($record) != RWS_ESSAY)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $qcat_id));
	$question = new stdClass();
	$question->qtype = RWS_ESSAY;
	$question->parent = 0;
	$question->hidden = 0;
	$question->length = 1;
	$question->category = $qcat_id;
	$question->stamp = make_unique_id_code();
	$question->createdby = $USER->id;
	$question->modifiedby = $USER->id;
	$question->penalty = 0;
	$pos = 1;
	$count = 4;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$data = unpack("N", $field);
	$size = $data[1];
	if (strlen($record) != $pos + $size)
		return FALSE;
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE || $count < 1)
		return FALSE;
	$field = substr($record, $pos, $count);
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->name = trim($field); 
	if (strlen($question->name) == 0)
		return FALSE;
	$question->name = clean_param($question->name, PARAM_TEXT);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->questiontext = trim($field); 
	$question->questiontextformat = FORMAT_HTML;
	$question->questiontext = clean_param($question->questiontext, PARAM_RAW);
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	$count++; 
	$pos += $count;
	$size -= $count;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$question->defaultmark = $data[1];
	else
		$question->defaultgrade = $data[1];
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$question->generalfeedback = trim($field); 
	$question->generalfeedbackformat = FORMAT_HTML;
	$question->generalfeedback = clean_param($question->generalfeedback, PARAM_RAW);
	$answer = new stdClass();
	$answer->fraction = 0; 
	if ($size < 1)
		return FALSE;
	$count = strpos(substr($record, $pos), "\0");
	if ($count === FALSE)
		return FALSE;
	if ($count > 0)
		$field = substr($record, $pos, $count);
	else
		$field = "";
	$count++; 
	$pos += $count;
	$size -= $count;
	$answer->feedback = trim($field); 
	$answer->feedbackformat = FORMAT_HTML;
	$answer->feedback = clean_param($answer->feedback, PARAM_RAW);
	$answer->answer = $answer->feedback;
	$answer->answerformat = $answer->feedbackformat;
	$count = 4;
	if ($size < $count)
		return FALSE;
	$field = substr($record, $pos, $count);
	$pos += $count;
	$size -= $count;
	$data = unpack("N", $field);
	$count = $data[1];
	if ($size < $count)
		return FALSE;
	$pos += $count;
	$size -= $count;
	$question->timecreated = time();
	$question->timemodified = time();
	$question->id = $DB->insert_record("question", $question);
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$text = $question->questiontext;
	$question->questiontext = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$text = $question->generalfeedback;
	$question->generalfeedback = RWSProcessAttachments($question->qtype,
	  $course_id, $contextid, $component, $filearea, $itemid, $text
	  );
	$DB->update_record("question", $question);
	$hash = question_hash($question);
	$DB->set_field("question", "version", $hash, array("id" => $question->id));
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$options = new stdClass();
		$options->questionid = $question->id;
		$options->responseformat = "editor"; 
		$options->responsefieldlines = 15; 
		$options->attachments = 0; 
		$options->graderinfo = $answer->answer;
		$options->graderinfoformat = $answer->answerformat;
		$options->id = $DB->insert_record("qtype_essay_options", $options);
		$component = "qtype_essay";
		$filearea = "graderinfo";
		$itemid = $question->id;
		$text = $options->graderinfo;
		$options->graderinfo = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$DB->update_record("qtype_essay_options", $options);
	}
	else { 
		$answer->question = $question->id;
		$answer->id = $DB->insert_record("question_answers", $answer);
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $answer->id;
		$text = $answer->feedback;
		$answer->feedback = RWSProcessAttachments($question->qtype,
		  $course_id, $contextid, $component, $filearea, $itemid, $text
		  );
		$answer->answer = $answer->feedback;
		$DB->update_record("question_answers", $answer);
	}
	return $question->id;
}
function RWSExportSettingsRecord($quiz)
{
	global $DB;
	global $RWS_LDB_INFO;
	global $CFG;
	$context = get_context_instance(CONTEXT_MODULE, $quiz->coursemodule);
	$contextid = $context->id;
	$text = $quiz->intro;
	$script = "pluginfile.php";
	$component = "mod_quiz";
	$filearea = "intro";
	$itemid = 0;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	if ($quiz->timeopen == 0) {
		$year = 0;
		$month = 0;
		$day = 0;
		$hour = 0;
		$minute = 0;
	}
	else {
		$start_date = usergetdate($quiz->timeopen);
		$year = $start_date['year'];
		$month = $start_date['mon'];
		$day = $start_date['mday'];
		$hour = $start_date['hours'];
		$minute = $start_date['minutes'];
	}
	$field = pack("nC*", $year, $month, $day, $hour, $minute);
	$record .= $field;
	if ($quiz->timeclose == 0) {
		$year = 0;
		$month = 0;
		$day = 0;
		$hour = 0;
		$minute = 0;
	}
	else {
		$end_date = usergetdate($quiz->timeclose);
		$year = $end_date['year'];
		$month = $end_date['mon'];
		$day = $end_date['mday'];
		$hour = $end_date['hours'];
		$minute = $end_date['minutes'];
	}
	$field = pack("nC*", $year, $month, $day, $hour, $minute);
	$record .= $field;
	$enable = ($quiz->timelimit == 0) ? 0 : 1;
	$minutes = $quiz->timelimit / 60;
	if ($minutes * 60 < $quiz->timelimit)
		$minutes += 1;
	$field = pack("CN", $enable, $minutes);
	$record .= $field;
	$field = $quiz->delay1;
	if ($field < 900)
		$field = 0; 
	else if ($field < 2700)
		$field = 1800; 
	else if ($field < 5400)
		$field = 3600; 
	else if ($field < 9000)
		$field = 7200; 
	else if ($field < 12600)
		$field = 10800; 
	else if ($field < 16200)
		$field = 14400; 
	else if ($field < 19800)
		$field = 18000; 
	else if ($field < 23400)
		$field = 21600; 
	else if ($field < 27000)
		$field = 25200; 
	else if ($field < 30600)
		$field = 28800; 
	else if ($field < 34200)
		$field = 32400; 
	else if ($field < 37800)
		$field = 36000; 
	else if ($field < 41400)
		$field = 39600; 
	else if ($field < 45000)
		$field = 43200; 
	else if ($field < 48600)
		$field = 46800; 
	else if ($field < 52200)
		$field = 50400; 
	else if ($field < 55800)
		$field = 54000; 
	else if ($field < 59400)
		$field = 57600; 
	else if ($field < 63000)
		$field = 61200; 
	else if ($field < 66600)
		$field = 64800; 
	else if ($field < 70200)
		$field = 68400; 
	else if ($field < 73800)
		$field = 72000; 
	else if ($field < 77400)
		$field = 75600; 
	else if ($field < 81000)
		$field = 79200; 
	else if ($field < 84600)
		$field = 82800; 
	else if ($field < 126000)
		$field = 86400; 
	else if ($field < 216000)
		$field = 172800; 
	else if ($field < 302400)
		$field = 259200; 
	else if ($field < 388800)
		$field = 345600; 
	else if ($field < 475200)
		$field = 432000; 
	else if ($field < 561600)
		$field = 518400; 
	else
		$field = 604800; 
	$field = pack("N", $field);
	$record .= $field;
	$field = $quiz->delay2;
	if ($field < 900)
		$field = 0; 
	else if ($field < 2700)
		$field = 1800; 
	else if ($field < 5400)
		$field = 3600; 
	else if ($field < 9000)
		$field = 7200; 
	else if ($field < 12600)
		$field = 10800; 
	else if ($field < 16200)
		$field = 14400; 
	else if ($field < 19800)
		$field = 18000; 
	else if ($field < 23400)
		$field = 21600; 
	else if ($field < 27000)
		$field = 25200; 
	else if ($field < 30600)
		$field = 28800; 
	else if ($field < 34200)
		$field = 32400; 
	else if ($field < 37800)
		$field = 36000; 
	else if ($field < 41400)
		$field = 39600; 
	else if ($field < 45000)
		$field = 43200; 
	else if ($field < 48600)
		$field = 46800; 
	else if ($field < 52200)
		$field = 50400; 
	else if ($field < 55800)
		$field = 54000; 
	else if ($field < 59400)
		$field = 57600; 
	else if ($field < 63000)
		$field = 61200; 
	else if ($field < 66600)
		$field = 64800; 
	else if ($field < 70200)
		$field = 68400; 
	else if ($field < 73800)
		$field = 72000; 
	else if ($field < 77400)
		$field = 75600; 
	else if ($field < 81000)
		$field = 79200; 
	else if ($field < 84600)
		$field = 82800; 
	else if ($field < 126000)
		$field = 86400; 
	else if ($field < 216000)
		$field = 172800; 
	else if ($field < 302400)
		$field = 259200; 
	else if ($field < 388800)
		$field = 345600; 
	else if ($field < 475200)
		$field = 432000; 
	else if ($field < 561600)
		$field = 518400; 
	else
		$field = 604800; 
	$field = pack("N", $field);
	$record .= $field;
	$field = $quiz->questionsperpage;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->shufflequestions;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->shuffleanswers;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->attempts;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->attemptonlast;
	$field = pack("C", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		if ($quiz->preferredbehaviour == "adaptive"
		  || $quiz->preferredbehaviour == "adaptivenopenalty")
			$field = 1;
		else
			$field = 0;
	}
	else { 
		$field = $quiz->optionflags & RWS_QUESTION_ADAPTIVE;
	}
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->grade;
	$field = pack("N", $field);
	$record .= $field;
	$field = $quiz->grademethod;
	$field = pack("C", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		if ($quiz->preferredbehaviour == "adaptive")
			$field = 1;
		else
			$field = 0;
	}
	else { 
		$field = $quiz->penaltyscheme;
	}
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->decimalpoints;
	if ($field > 3)
		$field = 3;
	$field = pack("C", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$responses = (($quiz->reviewattempt & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewattempt & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)) ? 1 : 0;
		$answers = (($quiz->reviewrightanswer & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewrightanswer & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)) ? 1 : 0;
		$feedback = (($quiz->reviewspecificfeedback & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewspecificfeedback & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)) ? 1 : 0;
		$general = (($quiz->reviewgeneralfeedback & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewgeneralfeedback & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)) ? 1 : 0;
		$scores = (($quiz->reviewmarks & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewmarks & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)
		  || ($quiz->reviewcorrectness & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewcorrectness & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)) ? 1 : 0;
		$overall = (($quiz->reviewoverallfeedback & RWS_QUIZ_REVIEW_DURING)
		  || ($quiz->reviewoverallfeedback & RWS_QUIZ_REVIEW_IMMEDIATELY_AFTER)) ? 1 : 0;
	}
	else { 
		$responses = ($quiz->review & RWS_QUIZ_REVIEW_RESPONSES & RWS_QUIZ_REVIEW_IMMEDIATELY) ? 1 : 0;
		$answers = ($quiz->review & RWS_QUIZ_REVIEW_ANSWERS & RWS_QUIZ_REVIEW_IMMEDIATELY) ? 1 : 0;
		$feedback = ($quiz->review & RWS_QUIZ_REVIEW_FEEDBACK & RWS_QUIZ_REVIEW_IMMEDIATELY) ? 1 : 0;
		$general = ($quiz->review & RWS_QUIZ_REVIEW_GENERALFEEDBACK & RWS_QUIZ_REVIEW_IMMEDIATELY) ? 1 : 0;
		$scores = ($quiz->review & RWS_QUIZ_REVIEW_SCORES & RWS_QUIZ_REVIEW_IMMEDIATELY) ? 1 : 0;
		$overall = ($quiz->review & RWS_QUIZ_REVIEW_OVERALLFEEDBACK & RWS_QUIZ_REVIEW_IMMEDIATELY) ? 1 : 0;
	}
	$field = pack("C*", $responses, $answers, $feedback, $general, $scores, $overall);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$responses = ($quiz->reviewattempt & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN) ? 1 : 0;
		$answers = ($quiz->reviewrightanswer & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN) ? 1 : 0;
		$feedback = ($quiz->reviewspecificfeedback & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN) ? 1 : 0;
		$general = ($quiz->reviewgeneralfeedback & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN) ? 1 : 0;
		$scores = (($quiz->reviewcorrectness & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN)
		  || ($quiz->reviewmarks & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN)) ? 1 : 0;
		$overall = ($quiz->reviewoverallfeedback & RWS_QUIZ_REVIEW_LATER_WHILE_OPEN) ? 1 : 0;
	}
	else { 
		$responses = ($quiz->review & RWS_QUIZ_REVIEW_RESPONSES & RWS_QUIZ_REVIEW_OPEN) ? 1 : 0;
		$answers = ($quiz->review & RWS_QUIZ_REVIEW_ANSWERS & RWS_QUIZ_REVIEW_OPEN) ? 1 : 0;
		$feedback = ($quiz->review & RWS_QUIZ_REVIEW_FEEDBACK & RWS_QUIZ_REVIEW_OPEN) ? 1 : 0;
		$general = ($quiz->review & RWS_QUIZ_REVIEW_GENERALFEEDBACK & RWS_QUIZ_REVIEW_OPEN) ? 1 : 0;
		$scores = ($quiz->review & RWS_QUIZ_REVIEW_SCORES & RWS_QUIZ_REVIEW_OPEN) ? 1 : 0;
		$overall = ($quiz->review & RWS_QUIZ_REVIEW_OVERALLFEEDBACK & RWS_QUIZ_REVIEW_OPEN) ? 1 : 0;
	}
	$field = pack("C*", $responses, $answers, $feedback, $general, $scores, $overall);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$responses = ($quiz->reviewattempt & RWS_QUIZ_REVIEW_AFTER_CLOSE) ? 1 : 0;
		$answers = ($quiz->reviewrightanswer & RWS_QUIZ_REVIEW_AFTER_CLOSE) ? 1 : 0;
		$feedback = ($quiz->reviewspecificfeedback & RWS_QUIZ_REVIEW_AFTER_CLOSE) ? 1 : 0;
		$general = ($quiz->reviewgeneralfeedback & RWS_QUIZ_REVIEW_AFTER_CLOSE) ? 1 : 0;
		$scores = (($quiz->reviewcorrectness & RWS_QUIZ_REVIEW_AFTER_CLOSE)
		  || ($quiz->reviewmarks & RWS_QUIZ_REVIEW_AFTER_CLOSE)) ? 1 : 0;
		$overall = ($quiz->reviewoverallfeedback & RWS_QUIZ_REVIEW_AFTER_CLOSE) ? 1 : 0;
	}
	else { 
		$responses = ($quiz->review & RWS_QUIZ_REVIEW_RESPONSES & RWS_QUIZ_REVIEW_CLOSED) ? 1 : 0;
		$answers = ($quiz->review & RWS_QUIZ_REVIEW_ANSWERS & RWS_QUIZ_REVIEW_CLOSED) ? 1 : 0;
		$feedback = ($quiz->review & RWS_QUIZ_REVIEW_FEEDBACK & RWS_QUIZ_REVIEW_CLOSED) ? 1 : 0;
		$general = ($quiz->review & RWS_QUIZ_REVIEW_GENERALFEEDBACK & RWS_QUIZ_REVIEW_CLOSED) ? 1 : 0;
		$scores = ($quiz->review & RWS_QUIZ_REVIEW_SCORES & RWS_QUIZ_REVIEW_CLOSED) ? 1 : 0;
		$overall = ($quiz->review & RWS_QUIZ_REVIEW_OVERALLFEEDBACK & RWS_QUIZ_REVIEW_CLOSED) ? 1 : 0;
	}
	$field = pack("C*", $responses, $answers, $feedback, $general, $scores, $overall);
	$record .= $field;
	$field = $quiz->popup;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->password;
	$field = pack("a*x", $field);
	$record .= $field;
	$field = $quiz->subnet;
	$field = pack("a*x", $field);
	$record .= $field;
	$field = $quiz->groupmode;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->visible;
	$field = pack("C", $field);
	$record .= $field;
	$field = $quiz->cmidnumber;
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "1"; 
	$field = pack("a*x", $field);
	$record .= $field;
	$feedbacktext = array();
	$feedbackboundaries = array();
	$quiz_feedback = $DB->get_records("quiz_feedback",
	  array("quizid" => $quiz->id), "mingrade DESC");
	if (count($quiz_feedback) > 0) {
		foreach ($quiz_feedback as $qf) {
			$text = $qf->feedbacktext;
			$script = "pluginfile.php";
			$component = "mod_quiz";
			$filearea = "feedback";
			$itemid = $qf->id;
			$feedbacktext[] = file_rewrite_pluginfile_urls(
			  $text, $script, $contextid, $component, $filearea, $itemid, null
			  );
            if ($qf->mingrade > 0) {
				$bound = (100.0 * $qf->mingrade / $quiz->grade) . "%";
				$feedbackboundaries[] = $bound;
			}
		}
	}
	$field = count($feedbacktext);
	$field = pack("C", $field);
	$record .= $field;
	if (count($feedbacktext) > 0) {
		foreach($feedbacktext as $feed) {
			$field = $feed;
			if (!RWSIsValidUtf8($field))
				$field = utf8_encode($field);
			$field = pack("a*x", $field);
			$record .= $field;
		}
	}
	$field = count($feedbackboundaries);
	$field = pack("C", $field);
	$record .= $field;
	foreach($feedbackboundaries as $bound) {
		$field = $bound;
		$field = pack("a*x", $field);
		$record .= $field;
	}
	RWSLoadLDBSettings($quiz);
	$field = $RWS_LDB_INFO->attempts;
	$field = pack("C", $field);
	$record .= $field;
	$field = $RWS_LDB_INFO->reviews;
	$field = pack("C", $field);
	$record .= $field;
	$field = $RWS_LDB_INFO->password;
	$field = pack("a*x", $field);
	$record .= $field;
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	return $record;
}
function RWSLoadLDBSettings($quiz)
{
	global $RWS_LDB_INFO;
	$RWS_LDB_INFO->attempts = 0; 
	$RWS_LDB_INFO->reviews = 0; 
	$RWS_LDB_INFO->password = ""; 
	$RWS_LDB_INFO->get_settings_err = FALSE;
	if ($RWS_LDB_INFO->module_ok) {
		$options = lockdown_get_quiz_options($quiz->instance);
		if (!$options)
			$RWS_LDB_INFO->get_settings_err = TRUE;
		else {
			$RWS_LDB_INFO->attempts = $options->attempts;
			$RWS_LDB_INFO->reviews = $options->reviews;
			$RWS_LDB_INFO->password = $options->password;
		}
	} else if ($RWS_LDB_INFO->block_ok) {
		$options = lockdown_get_quiz_options($quiz->instance);
		if (!$options)
			$RWS_LDB_INFO->get_settings_err = TRUE;
		else {
			$RWS_LDB_INFO->attempts = $options->attempts;
		}
	}
}
function RWSExportReservedRecord($data)
{
	$record = "";
	$len = strlen($data);
	if ($len > 0)
		$record .= $data;
	if ($len > 0) {
		$field = crc32($data);
		$field = pack("N", $field);
		$record .= $field;
	}
	$rdata  = pack("C", 12); 
	$rdata .= pack("N", strlen($record)); 
	$rdata .= $record; 
	return $rdata;
}
function RWSExportShortAnswerRecord($question)
{
	global $DB;
	global $CFG;
	if ($question->qtype != RWS_SHORTANSWER)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$field = $question->defaultmark;
	else
		$field = $question->defaultgrade;
	if ($field < 0)
		$field = 0;
	$field = pack("N", $field);
	$record .= $field;
	$field = $question->penalty;
	$field = RWSDoubleToIEEE754($field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$options = $DB->get_record("question_shortanswer",
	  array("question" => $question->id));
	if ($options === FALSE)
		return FALSE;
	$field = $options->usecase;
	$field = pack("C", $field);
	$record .= $field;
	$answers = array();
	$answer_ids = explode(",", $options->answers);
	foreach($answer_ids as $id) {
		$answer = $DB->get_record("question_answers", array("id" => $id));
		if ($answer === FALSE)
			return FALSE;
		$answers[] = $answer;
	}
	$field = count($answers);
	$field = pack("C", $field);
	$record .= $field;
	foreach($answers as $answer) {
		$field = $answer->answer;
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
		$field = $answer->fraction;
		if (RWSFloatCompare($behavior_version, 2011020100, 2) == -1) {
			switch (strval($field)) {
			case "0.8333333":
				$field = "0.83333";
				break;
			case "0.6666667":
				$field = "0.66666";
				break;
			case "0.3333333":
				$field = "0.33333";
				break;
			case "0.1666667":
				$field = "0.16666";
				break;
			case "0.1428571":
				$field = "0.142857";
				break;
			case "0.1111111":
				$field = "0.11111";
				break;
			default:
				break;
			}
		}
		$field = RWSDoubleToIEEE754($field);
		$record .= $field;
		$text = $answer->feedback;
		$script = "pluginfile.php";
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $answer->id;
		$field = file_rewrite_pluginfile_urls(
		  $text, $script, $contextid, $component, $filearea, $itemid, null
		  );
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
	}
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 3); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSExportTrueFalseRecord($question)
{
	global $DB;
	global $CFG;
	if ($question->qtype != RWS_TRUEFALSE)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$field = $question->defaultmark;
	else
		$field = $question->defaultgrade;
	if ($field < 0)
		$field = 0;
	$field = pack("N", $field);
	$record .= $field;
	$field = $question->penalty;
	$field = RWSDoubleToIEEE754($field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$options = $DB->get_record("question_truefalse",
	  array("question" => $question->id));
	if ($options === FALSE)
		return FALSE;
	$true = $DB->get_record("question_answers",
	  array("id" => $options->trueanswer));
	if ($true === FALSE)
		return FALSE;
	$false = $DB->get_record("question_answers",
	  array("id" => $options->falseanswer));
	if ($false === FALSE)
		return FALSE;
	$field = $true->fraction;
	$field = pack("C", $field);
	$record .= $field;
	$text = $true->feedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "answerfeedback";
	$itemid = $true->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$text = $false->feedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "answerfeedback";
	$itemid = $false->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 2); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSExportMultiAnswerRecord($question)
{
	global $DB;
	if ($question->qtype != RWS_MULTIANSWER)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$question->questiontext = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	$cloze_fields = RWSGetClozeFields($question->questiontext);
	if ($cloze_fields === FALSE)
		return FALSE;
	$options = $DB->get_record("question_multianswer",
	  array("question" => $question->id));
	if ($options === FALSE)
		return FALSE;
	$child_ids = explode(",", $options->sequence);
	$child_count = count($child_ids);
	if ($child_count != count($cloze_fields))
		return FALSE;
	for ($i = 0; $i < $child_count; $i++) {
		$child = $DB->get_record("question", array("id" => $child_ids[$i]));
		if ($child === FALSE)
			return FALSE;
		$text = $child->questiontext;
		$script = "pluginfile.php";
		$component = "question";
		$filearea = "questiontext";
		$itemid = $child->id;
		$child->questiontext = file_rewrite_pluginfile_urls(
		  $text, $script, $contextid, $component, $filearea, $itemid, null
		  );
		$question->questiontext = implode($child->questiontext,
		  explode($cloze_fields[$i], $question->questiontext, 2));
	}
	$field = $question->questiontext;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	$field = $question->penalty;
	$field = RWSDoubleToIEEE754($field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 9); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSCompareRecordsForIdSort($rec1, $rec2)
{
	if ($rec1->id == $rec2->id)
		return 0;
	return ($rec1->id < $rec2->id) ? -1 : 1;
}
function RWSExportCalculatedRecord($question)
{
	global $DB;
	global $CFG;
	if ($question->qtype != RWS_CALCULATED
	  && $question->qtype != RWS_CALCULATEDSIMPLE)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$field = $question->defaultmark;
	else
		$field = $question->defaultgrade;
	if ($field < 0)
		$field = 0;
	$field = pack("N", $field);
	$record .= $field;
	$field = $question->penalty;
	$field = RWSDoubleToIEEE754($field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$answers = $DB->get_records("question_answers",
	  array("question" => $question->id));
	if (count($answers) == 0)
		return FALSE;
	if (count($answers) > 1)
		usort($answers, "RWSCompareRecordsForIdSort");
	$field = count($answers);
	$field = pack("C", $field);
	$record .= $field;
	foreach($answers as $ans) {
		$field = $ans->answer;
		$field = pack("a*x", $field);
		$record .= $field;
		$field = $ans->fraction;
		if (RWSFloatCompare($behavior_version, 2011020100, 2) == -1) {
			switch (strval($field)) {
			case "0.8333333":
				$field = "0.83333";
				break;
			case "0.6666667":
				$field = "0.66666";
				break;
			case "0.3333333":
				$field = "0.33333";
				break;
			case "0.1666667":
				$field = "0.16666";
				break;
			case "0.1428571":
				$field = "0.142857";
				break;
			case "0.1111111":
				$field = "0.11111";
				break;
			default:
				break;
			}
		}
		$field = RWSDoubleToIEEE754($field);
		$record .= $field;
		$text = $ans->feedback;
		$script = "pluginfile.php";
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $ans->id;
		$field = file_rewrite_pluginfile_urls(
		  $text, $script, $contextid, $component, $filearea, $itemid, null
		  );
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
		$opt = $DB->get_record("question_calculated",
		  array("answer" => $ans->id));
		if ($opt === FALSE)
			return FALSE;
		$field = $opt->tolerance;
		$field = RWSDoubleToIEEE754($field);
		$record .= $field;
		$field = $opt->tolerancetype;
		$field = pack("C", $field);
		$record .= $field;
		$field = $opt->correctanswerlength;
		$field = pack("C", $field);
		$record .= $field;
		$field = $opt->correctanswerformat;
		$field = pack("C", $field);
		$record .= $field;
	}
	$units = $DB->get_records("question_numerical_units",
	  array("question" => $question->id));
	if (count($units) > 1)
		usort($units, "RWSCompareRecordsForIdSort");
	$field = count($units);
	$field = pack("C", $field);
	$record .= $field;
	if (count($units) > 0) {
		foreach($units as $unit) {
			$field = $unit->unit;
			$field = pack("a*x", $field);
			$record .= $field;
			$field = $unit->multiplier;
			$field = RWSDoubleToIEEE754($field);
			$record .= $field;
		}
	}
	$datasets = $DB->get_records("question_datasets",
	  array("question" => $question->id));
	if (count($datasets) == 0)
		return FALSE;
	$field = count($datasets);
	$field = pack("C", $field);
	$record .= $field;
	foreach($datasets as $qds) {
		$def = $DB->get_record("question_dataset_definitions",
		  array("id" => $qds->datasetdefinition));
		if ($def === FALSE)
			return FALSE;
		$field = $def->name;
		$field = pack("a*x", $field);
		$record .= $field;
		list($distribution, $min, $max, $precision) =
		  explode(":", $def->options, 4);
		$field = $distribution;
		$field = pack("a*x", $field);
		$record .= $field;
		$field = $min;
		$field = RWSDoubleToIEEE754($field);
		$record .= $field;
		$field = $max;
		$field = RWSDoubleToIEEE754($field);
		$record .= $field;
		$field = $precision;
		$field = pack("C", $field);
		$record .= $field;
		$field = $def->type;
		$field = pack("C", $field);
		$record .= $field;
		if ($def->category == 0)
			$field = 0; 
		else 
			$field = 1;
		$field = pack("C", $field);
		$record .= $field;
		$items = $DB->get_records("question_dataset_items",
		  array("definition" => $def->id));
		if (count($items) == 0)
			return FALSE;
		$field = count($items);
		$field = pack("C", $field);
		$record .= $field;
		foreach($items as $item) {
			$field = $item->itemnumber;
			$field = pack("C", $field);
			$record .= $field;
			$field = $item->value;
			$field = RWSDoubleToIEEE754($field);
			$record .= $field;
		}
	}
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 7); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSExportMultipleChoiceRecord($question)
{
	global $DB;
	global $CFG;
	if ($question->qtype != RWS_MULTICHOICE)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$field = $question->defaultmark;
	else
		$field = $question->defaultgrade;
	if ($field < 0)
		$field = 0;
	$field = pack("N", $field);
	$record .= $field;
	$field = $question->penalty;
	$field = RWSDoubleToIEEE754($field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$options = $DB->get_record("question_multichoice",
	  array("question" => $question->id));
	if ($options === FALSE)
		return FALSE;
	$field = $options->single;
	$field = pack("C", $field);
	$record .= $field;
	$field = $options->shuffleanswers;
	$field = pack("C", $field);
	$record .= $field;
	$field = $options->answernumbering;
	$field = pack("a*x", $field);
	$record .= $field;
	$answers = array();
	$answer_ids = explode(",", $options->answers);
	foreach($answer_ids as $id) {
		$answer = $DB->get_record("question_answers", array("id" => $id));
		if ($answer === FALSE)
			return FALSE;
		$answers[] = $answer;
	}
	$field = count($answers);
	$field = pack("C", $field);
	$record .= $field;
	foreach($answers as $answer) {
		$text = $answer->answer;
		$script = "pluginfile.php";
		$component = "question";
		$filearea = "answer";
		$itemid = $answer->id;
		$field = file_rewrite_pluginfile_urls(
		  $text, $script, $contextid, $component, $filearea, $itemid, null
		  );
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
		$field = $answer->fraction;
		if (RWSFloatCompare($behavior_version, 2011020100, 2) == -1) {
			switch (strval($field)) {
			case "0.8333333":
				$field = "0.83333";
				break;
			case "0.6666667":
				$field = "0.66666";
				break;
			case "0.3333333":
				$field = "0.33333";
				break;
			case "0.1666667":
				$field = "0.16666";
				break;
			case "0.1428571":
				$field = "0.142857";
				break;
			case "0.1111111":
				$field = "0.11111";
				break;
			case "-0.1111111":
				$field = "-0.11111";
				break;
			case "0.1428571":
				$field = "-0.142857";
				break;
			case "0.1666667":
				$field = "-0.16666";
				break;
			case "0.3333333":
				$field = "-0.33333";
				break;
			case "0.6666667":
				$field = "-0.66666";
				break;
			case "0.8333333":
				$field = "-0.83333";
				break;
			default:
				break;
			}
		}
		$field = RWSDoubleToIEEE754($field);
		$record .= $field;
		$text = $answer->feedback;
		$script = "pluginfile.php";
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $answer->id;
		$field = file_rewrite_pluginfile_urls(
		  $text, $script, $contextid, $component, $filearea, $itemid, null
		  );
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
	}
	$text = $options->correctfeedback;
	$script = "pluginfile.php";
	$component = "qtype_multichoice";
	$filearea = "correctfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$text = $options->partiallycorrectfeedback;
	$script = "pluginfile.php";
	$component = "qtype_multichoice";
	$filearea = "partiallycorrectfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$text = $options->incorrectfeedback;
	$script = "pluginfile.php";
	$component = "qtype_multichoice";
	$filearea = "incorrectfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 1); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSExportMatchingRecord($question)
{
	global $DB;
	global $CFG;
	if ($question->qtype != RWS_MATCH)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$field = $question->defaultmark;
	else
		$field = $question->defaultgrade;
	if ($field < 0)
		$field = 0;
	$field = pack("N", $field);
	$record .= $field;
	$field = $question->penalty;
	$field = RWSDoubleToIEEE754($field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$options = $DB->get_record("question_match",
	  array("question" => $question->id));
	if ($options === FALSE)
		return FALSE;
	$field = $options->shuffleanswers;
	$field = pack("C", $field);
	$record .= $field;
	$pairs = array();
	$pair_ids = explode(",", $options->subquestions);
	foreach($pair_ids as $id) {
		$pair = $DB->get_record("question_match_sub", array("id" => $id));
		if ($pair === FALSE)
			return FALSE;
		$pairs[] = $pair;
	}
	$field = count($pairs);
	$field = pack("C", $field);
	$record .= $field;
	foreach($pairs as $pair) {
		$text = $pair->questiontext;
		$script = "pluginfile.php";
		$component = "qtype_match";
		$filearea = "subquestion";
		$itemid = $pair->id;
		$field = file_rewrite_pluginfile_urls(
		  $text, $script, $contextid, $component, $filearea, $itemid, null
		  );
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
		$field = $pair->answertext;
		if (!RWSIsValidUtf8($field))
			$field = utf8_encode($field);
		$field = pack("a*x", $field);
		$record .= $field;
	}
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 5); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSExportDescriptionRecord($question)
{
	global $DB;
	if ($question->qtype != RWS_DESCRIPTION)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 6); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSExportEssayRecord($question)
{
	global $DB;
	global $CFG;
	if ($question->qtype != RWS_ESSAY)
		return FALSE;
	if ($question->parent != 0)
		return FALSE;
	$contextid = $DB->get_field("question_categories", "contextid",
	  array("id" => $question->category));
	$field = $question->name;
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record = $field;
	$text = $question->questiontext;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "questiontext";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = "";
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
		$field = $question->defaultmark;
	else
		$field = $question->defaultgrade;
	if ($field < 0)
		$field = 0;
	$field = pack("N", $field);
	$record .= $field;
	$text = $question->generalfeedback;
	$script = "pluginfile.php";
	$component = "question";
	$filearea = "generalfeedback";
	$itemid = $question->id;
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
		$options = $DB->get_record("qtype_essay_options",
		  array("questionid" => $question->id));
		$text = $options->graderinfo;
		$component = "qtype_essay";
		$filearea = "graderinfo";
		$itemid = $question->id;
	}
	else { 
		$answer = $DB->get_record("question_answers",
		  array("question" => $question->id));
		if ($answer === FALSE)
			return FALSE;
		$text = $answer->feedback;
		$script = "pluginfile.php";
		$component = "question";
		$filearea = "answerfeedback";
		$itemid = $answer->id;
	}
	$script = "pluginfile.php";
	$field = file_rewrite_pluginfile_urls(
	  $text, $script, $contextid, $component, $filearea, $itemid, null
	  );
	if (!RWSIsValidUtf8($field))
		$field = utf8_encode($field);
	$field = pack("a*x", $field);
	$record .= $field;
	$field = 8; 
	$field = pack("N", $field);
	$record .= $field;
	$field = time();
	$field = pack("N", $field);
	$record .= $field;
	$field = crc32($record);
	$field = pack("N", $field);
	$record .= $field;
	$qdata  = pack("C", 4); 
	$qdata .= pack("N", strlen($record)); 
	$qdata .= $record; 
	return $qdata;
}
function RWSCompressExportData($uncompressed_file, $compressed_file)
{
	$src_paths = array(
		basename($uncompressed_file) => $uncompressed_file
		);
	$packer = get_file_packer("application/zip");
	$ok = $packer->archive_to_pathname($src_paths, $compressed_file);
	return $ok;
}
function RWSDecompressImportData($file_data, $import_dir)
{
	$clean_tmpfile = FALSE;
	$tmppath = RWSGetTempPath();
	$tmpfile = tempnam($tmppath, "rws");
	$ok = ($tmpfile !== FALSE);
	if ($ok) {
		$ext = pathinfo($tmpfile, PATHINFO_EXTENSION);
		if (empty($ext)) {
			$oldname = $tmpfile;
			$tmpfile .= ".tmp";
			if (file_exists($tmpfile))
				unlink($tmpfile);
			$ok = rename($oldname, $tmpfile);
		}
	}
	if ($ok) {
		$tmp = fopen($tmpfile, "wb"); 
		$ok = ($tmp !== FALSE);
		$clean_tmpfile = $ok;
	}
	if ($ok) {
		$bytes = fwrite($tmp, $file_data);
		$ok = ($bytes !== FALSE);
	}
	if ($clean_tmpfile)
		fclose($tmp);
	if ($ok) {
		$packer = get_file_packer("application/zip");
		$results = $packer->extract_to_pathname($tmpfile, $import_dir);
		if ($results === FALSE)
			$ok = FALSE;
		if ($ok) {
			foreach ($results as $name => $status) {
				if ($status !== true) {
					$ok = FALSE;
					break;
				}
			}
		}
	}
	if ($clean_tmpfile && file_exists($tmpfile))
		unlink($tmpfile);
	return $ok;
}
function RWSMakeTempFolder()
{
	global $CFG;
	if (RWSFloatCompare($CFG->version, 2011120500.00, 2) >= 0) { 
		$tmppath = make_temp_directory("rws" . time());
		return $tmppath;
	}
	else { 
		$tmppath = RWSGetTempPath();
		$ok = ($tmppath !== FALSE);
		if ($ok) {
			$tmpfile = tempnam($tmppath, "rws");
			$ok = ($tmpfile !== FALSE);
		}
		if ($ok && file_exists($tmpfile))
			$ok = unlink($tmpfile);
		if ($ok)
			$ok = mkdir($tmpfile);
		if ($ok)
			return $tmpfile;
		else
			return FALSE;
	}
}
function RWSExportQCatQuestions($qcat_id, &$qfile, &$dropped, $want_base64)
{
	global $DB;
    $dropped = 0;
	$qdata = "";
	$qtops = array();
	$questions = $DB->get_records("question", array("category" => $qcat_id));
	if (count($questions) > 0) {
		foreach ($questions as $q) {
			if ($q->parent == 0)
				$qtops[] = $q;
		}
	}
	if (count($qtops) < 1) {
		RWSServiceError("2102");
	}
	$random = 0;
	$qdata = RWSExportQuestions(
	  $qtops, $qfile, $dropped, $random, $want_base64);
	return $qdata;
}
function RWSExportQuizQuestions(
  $quiz_cmid, &$qfile, &$dropped, &$random, $want_base64)
{
	global $DB;
    $dropped = 0;
    $random = 0;
	$missing = 0;
	$course_module = $DB->get_record("course_modules",
	  array("id" => $quiz_cmid));
	if ($course_module === FALSE)
		RWSServiceError("2042"); 
	$modrec = $DB->get_record("modules",
	  array("id" => $course_module->module));
    if ($modrec === FALSE) 
        RWSServiceError("2043");
 	$quiz = $DB->get_record($modrec->name,
	  array("id" => $course_module->instance));
	if ($quiz === FALSE) 
        RWSServiceError("2044");
    $qdata = "";
    $qids = explode(",", $quiz->questions);
	$questions = array();
	if ($qids !== FALSE) {
		foreach ($qids as $id) {
			if ($id == "0")
				continue; 
			$q = $DB->get_record("question", array("id" => $id));
			if ($q !== FALSE)
				$questions[] = $q;
			else
				$missing++;
		}
	}
	if (count($questions) < 1) {
		RWSServiceError("2103");
	}
	$qdata = RWSExportQuestions(
	  $questions, $qfile, $dropped, $random, $want_base64);
	$dropped += $missing;
	return $qdata;
}
function RWSExportQuestions(
  $questions, &$qfile, &$dropped, &$random, $want_base64)
{
		$format_version = 0; 
	$fname_compressed = "rwsexportqdata.zip";
	$fname_uncompressed = "rwsexportqdata.dat";
	$qfile = "";
	$exported = 0;
	$dropped = 0;
	$random = 0;
	$clean_export_dir = FALSE;
	$clean_export_file = FALSE;
	$clean_compressed_file = FALSE;
	$close_export_file = FALSE;
	$ok = (count($questions) > 0);
	if (!$ok)
		return "";
	if ($ok) {
		$export_dir = RWSMakeTempFolder();
		$ok = ($export_dir !== FALSE);
		$clean_export_dir = $ok;
		if (!$ok)
			$error = "2045"; 
	}
	if ($ok) {
		$export_file = "$export_dir/$fname_uncompressed";
		$handle = fopen($export_file, "wb"); 
		$ok = ($handle !== FALSE);
		$clean_export_file = $ok;
		$close_export_file = $ok;
		if (!$ok)
			$error = "2046"; 
	}
	if ($ok) {
			$data = pack("C*", 0xc7, 0x89, 0xf0, 0x4c, 0xa4, 0x03, 0x47, 0x9b,
			  0xa3, 0x7b, 0x29, 0xc6, 0xad, 0xd5, 0x30, 0x81);
		$data .= pack("n", $format_version);
		$bytes = fwrite($handle, $data);
		$ok = ($bytes !== FALSE);
		if (!$ok)
			$error = "2047"; 
	}
	if ($ok) {
		$i = 0;
		foreach ($questions as $q) {
			$i++;
			if ($i % 10 == 0) {
				$record = RWSExportReservedRecord(time());
				$ok2 = ($record !== FALSE);
				if ($ok2)
					RWSWriteNextQuestionRecord($handle, $record);
			}
			switch ($q->qtype) {
			case RWS_SHORTANSWER:
				$record = RWSExportShortAnswerRecord($q);
				break;
			case RWS_TRUEFALSE:
				$record = RWSExportTrueFalseRecord($q);
				break;
			case RWS_MULTICHOICE:
				$record = RWSExportMultipleChoiceRecord($q);
				break;
			case RWS_MATCH:
				$record = RWSExportMatchingRecord($q);
				break;
			case RWS_DESCRIPTION:
				$record = RWSExportDescriptionRecord($q);
				break;
			case RWS_ESSAY:
				$record = RWSExportEssayRecord($q);
				break;
			case RWS_CALCULATEDSIMPLE:
			case RWS_CALCULATED:
				$record = RWSExportCalculatedRecord($q);
				break;
			case RWS_MULTIANSWER: 
				$record = RWSExportMultiAnswerRecord($q);
				break;
			case RWS_RANDOM:
				$random++;
				$record = FALSE;
				break;
			case RWS_CALCULATEDMULTI:
			case RWS_NUMERICAL:
			case RWS_RANDOMSAMATCH:
			default:
				$record = FALSE;
				break;
			}
			$ok2 = ($record !== FALSE);
			if ($ok2)
				$ok2 = RWSWriteNextQuestionRecord($handle, $record);
			if ($ok2)
				$exported++;
			else
				$dropped++;
		}
    }
	if ($close_export_file)
		fclose($handle);
	if ($ok && $exported > 0) {
		$compressed_file = "$export_dir/$fname_compressed";
		$ok = RWSCompressExportData($export_file, $compressed_file);
		$clean_compressed_file = $ok;
		if (!$ok)
			$error = "2048"; 
	}
	if ($ok && $exported > 0) {
		$compressed = file_get_contents($compressed_file);
		$ok = ($compressed !== FALSE);
		if (!$ok)
			$error = "2049"; 
	}
	if ($ok && $exported > 0 && $want_base64)
		$encoded = base64_encode($compressed);
	if ($clean_export_file && file_exists($export_file))
		unlink($export_file);
	if ($clean_compressed_file && file_exists($compressed_file))
		unlink($compressed_file);
	if ($clean_export_dir && file_exists($export_dir))
		rmdir($export_dir);
	if (!$ok)
		RWSServiceError($error);
	if ($exported == 0) {
		RWSServiceError("2104");
	}
	$qfile = $fname_compressed;
	if ($want_base64)
		return $encoded;
	else
		return $compressed;
}
function RWSUpdateQuizGrades($quiz)
{
	$grade_item = grade_item::fetch(array('itemtype'=>'mod',
	  'itemmodule'=>$quiz->modulename, 'iteminstance'=>$quiz->instance,
	  'itemnumber'=>0, 'courseid'=>$quiz->course));
     if ($grade_item && $grade_item->idnumber != $quiz->cmidnumber) {
         $grade_item->idnumber = $quiz->cmidnumber;
         $grade_item->update();
     }
    $items = grade_item::fetch_all(array('itemtype'=>'mod',
	  'itemmodule'=>$quiz->modulename, 'iteminstance'=>$quiz->instance,
	  'courseid'=>$quiz->course));
    if ($items && isset($quiz->gradecat)) {
        if ($quiz->gradecat == -1) {
            $grade_category = new grade_category();
            $grade_category->courseid = $quiz->course;
            $grade_category->fullname = $quiz->name;
            $grade_category->insert();
            if ($grade_item) {
                $parent = $grade_item->get_parent_category();
                $grade_category->set_parent($parent->id);
            }
            $quiz->gradecat = $grade_category->id;
        }
        foreach ($items as $itemid=>$unused) {
            $items[$itemid]->set_parent($quiz->gradecat);
            if ($itemid == $grade_item->id)
                $grade_item = $items[$itemid]; 
        }
    }
    if ($outcomes = grade_outcome::fetch_all_available($quiz->course)) {
        $grade_items = array();
        $max_itemnumber = 999;
        if ($items) {
            foreach($items as $item) {
                if ($item->itemnumber > $max_itemnumber)
                    $max_itemnumber = $item->itemnumber;
            }
        }
        foreach($outcomes as $outcome) {
            $elname = 'outcome_'.$outcome->id;
            if (property_exists($quiz, $elname) and $quiz->$elname) {
                if ($items) {
                    foreach($items as $item) {
                        if ($item->outcomeid == $outcome->id)
                            continue 2; 
                    }
                }
                $max_itemnumber++;
                $outcome_item = new grade_item();
                $outcome_item->courseid     = $quiz->course;
                $outcome_item->itemtype     = 'mod';
                $outcome_item->itemmodule   = $quiz->modulename;
                $outcome_item->iteminstance = $quiz->instance;
                $outcome_item->itemnumber   = $max_itemnumber;
                $outcome_item->itemname     = $outcome->fullname;
                $outcome_item->outcomeid    = $outcome->id;
                $outcome_item->gradetype    = GRADE_TYPE_SCALE;
                $outcome_item->scaleid      = $outcome->scaleid;
                $outcome_item->insert();
                if ($grade_item) {
                    $outcome_item->set_parent($grade_item->categoryid);
                    $outcome_item->move_after_sortorder($grade_item->sortorder);
                } else if (isset($quiz->gradecat)) {
                    $outcome_item->set_parent($quiz->gradecat);
                }
            }
        }
    }
}
function RWSDeleteQuestionCategory($qcat_id)
{
	global $DB;
	global $CFG;
	$children = $DB->get_records("question_categories",
	  array("parent" => $qcat_id));
	if (count($children) > 0) {
		foreach ($children as $child)
			RWSDeleteQuestionCategory($child->id);
	}
	$questions = $DB->get_records("question", array("category" => $qcat_id));
	if (count($questions) > 0) {
		foreach ($questions as $q) {
			if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
				question_delete_question($q->id);
			else
				delete_question($q->id);
		}
		$DB->delete_records("question", array("category" => $qcat_id));
	}
	$DB->delete_records("question_categories", array("id" => $qcat_id));
}
function RWSIsQuestionCategoryInUse($qcat_id)
{
	global $DB;
	global $CFG;
	$children = $DB->get_records("question_categories",
	  array("parent" => $qcat_id));
	if (count($children) > 0) {
		foreach ($children as $child) {
			if (RWSIsQuestionCategoryInUse($child->id))
				return TRUE;
		}
	}
	$questions = $DB->get_records("question", array("category" => $qcat_id));
	if (count($questions) > 0) {
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
			$qids = array();
			foreach ($questions as $q)
				$qids[] = $q->id;
			if (questions_in_use($qids))
				return TRUE;
		}
		else { 
			foreach ($questions as $q) {
				if (count(question_list_instances($q->id)) > 0)
					return TRUE;
			}
		}
	}
	return FALSE;	
}
function RWSProcessAttachments(
  $qtype, $course_id, $contextid, $component, $filearea, $itemid, $text)
{
	global $USER;
	$len = strlen($text);
	$out = "";
	$pos = 0;
	$src_context = get_context_instance(CONTEXT_COURSE, $course_id);
	$src_urlparm = "%%COURSEPATH%%";
	$dst_urlparm = "@@PLUGINFILE@@";
	while ($pos < $len)	{
		$next = strpos($text, "$src_urlparm/", $pos);
		if ($next === FALSE)
			break;
		$start = $pos;
		$end = $next;
		$out .= substr($text, $start, $end - $start);
		$start = $next + strlen("$src_urlparm/");
		$end = strpos($text, "/", $start);
		if ($end === FALSE) {
			$end = $start;
			$start = $next;
			$out .= substr($text, $start, $end - $start);
			$pos = $end;
			continue;
		}
		$file_folder = substr($text, $start, $end - $start);
		$start = $end + 1;
		$end = strpos($text, "\"", $start);
		if ($end === FALSE) {
			$end = $start;
			$start = $next;
			$out .= substr($text, $start, $end - $start);
			$pos = $end;
			continue;
		}
		$file_name = substr($text, $start, $end - $start);
		$pos = $end;
		$src_contextid = $src_context->id;
		$src_component = "mod_respondusws";
		$src_filearea = "upload";
		$src_itemid = $USER->id;
		$src_filepath = "/$file_folder/";
		$src_filename = $file_name;
		$dst_contextid = $contextid;
		$dst_component = $component;
		$dst_filearea = $filearea;
		$dst_itemid = $itemid;
		$dst_filepath = "/";
		$dst_filename = $file_name;
		try {
			$fs = get_file_storage();
			$file = $fs->get_file($src_contextid, $src_component,
			  $src_filearea, $src_itemid, $src_filepath, $src_filename);
		} catch (Exception $e) {
			$file = FALSE;
		}
		if ($file === FALSE) {
			$start = $next;
			$end = $pos;
			$out .= substr($text, $start, $end - $start);
			continue;
		}
		try {
			$file_exists = $fs->file_exists($dst_contextid, $dst_component,
			  $dst_filearea, $dst_itemid, $dst_filepath, $dst_filename);
			if ($file_exists == FALSE) {
				$fileinfo = array(
				  "contextid" => $dst_contextid, "component" => $dst_component,
				  "filearea" => $dst_filearea, "itemid" => $dst_itemid,
				  "filepath" => $dst_filepath, "filename" => $dst_filename
				  );
				if ($fs->create_file_from_storedfile($fileinfo, $file))
					$file_exists = TRUE;
			}
		} catch (Exception $e) {
			$file_exists = FALSE;
		}
		if ($file_exists == FALSE) {
			$start = $next;
			$end = $pos;
			$out .= substr($text, $start, $end - $start);
			continue;
		}
		$url = $dst_urlparm . $dst_filepath . $dst_filename;
		$out .= $url;
	}
	if ($pos < $len) {
		$start = $pos;
		$end = $len;
		$out .= substr($text, $start, $end - $start);
	}
	return $out;
}
function RWSIsValidUtf8($string)
{ 
	$len = strlen($string);
	$i = 0;
	while ($i < $len) {
		$c0 = ord($string[$i]);
		if ($i+1 < $len)
			$c1 = ord($string[$i+1]);
		if ($i+2 < $len)
			$c2 = ord($string[$i+2]);
		if ($i+3 < $len)
			$c3 = ord($string[$i+3]);
		if ($c0 >= 0x00 && $c0 <= 0x7e) {
			$i++;
		}
		else if ($i+1 < $len
		  && $c0 >= 0xc2 && $c0 <= 0xdf
		  && $c1 >= 0x80 && $c1 <= 0xbf) {
			$i += 2;
		}
		else if ($i+2 < $len
		  && $c0 == 0xe0
		  && $c1 >= 0xa0 && $c1 <= 0xbf
		  && $c2 >= 0x80 && $c2 <= 0xbf) {
			$i += 3;
		}
		else if ($i+2 < $len
		  && (($c0 >= 0xe1 && $c0 <= 0xec) || $c0 == 0xee || $c0 == 0xef)
		  && $c1 >= 0x80 && $c1 <= 0xbf
		  && $c2 >= 0x80 && $c2 <= 0xbf) {
			$i += 3;
		}
		else if ($i+2 < $len
		  && $c0 == 0xed
		  && $c1 >= 0x80 && $c1 <= 0x9f
		  && $c2 >= 0x80 && $c2 <= 0xbf) {
			$i += 3;
		}
		else if ($i+3 < $len
		  && $c0 == 0xf0
		  && $c1 >= 0x90 && $c1 <= 0xbf
		  && $c2 >= 0x80 && $c2 <= 0xbf
		  && $c3 >= 0x80 && $c3 <= 0xbf) {
			$i += 4;
		}
		else if ($i+3 < $len
		  && $c0 >= 0xf1 && $c0 <= 0xf3
		  && $c1 >= 0x80 && $c1 <= 0xbf
		  && $c2 >= 0x80 && $c2 <= 0xbf
		  && $c3 >= 0x80 && $c3 <= 0xbf) {
			$i += 4;
		}
		else if ($i+3 < $len
		  && $c0 == 0xf4
		  && $c1 >= 0x80 && $c1 <= 0x8f
		  && $c2 >= 0x80 && $c2 <= 0xbf
		  && $c3 >= 0x80 && $c3 <= 0xbf) {
			$i += 4;
		}
		else {
			return FALSE;
		}
	}
	return TRUE;
}
function RWSDispatchServiceAction($action)
{
	RWSErrorLog("action=$action");
	if ($action == "phpinfo")
		RWSActionPHPInfo();
	else if ($action == "serviceinfo")
		RWSActionServiceInfo();
	else if ($action == "login")
		RWSActionLogin();
	else if ($action == "logout")
		RWSActionLogout();
	else if ($action == "courselist")
		RWSActionCourseList();
	else if ($action == "sectionlist")
		RWSActionSectionList();
	else if ($action == "quizlist")
		RWSActionQuizList();
	else if ($action == "qcatlist")
		RWSActionQCatList();
	else if ($action == "addqcat")
		RWSActionAddQCat();
	else if ($action == "deleteqcat")
		RWSActionDeleteQCat();
	else if ($action == "deletequiz")
		RWSActionDeleteQuiz();
	else if ($action == "addquiz")
		RWSActionAddQuiz();
	else if ($action == "updatequiz")
		RWSActionUpdateQuiz();
	else if ($action == "addqlist")
		RWSActionAddQList();
	else if ($action == "addqrand")
		RWSActionAddQRand();
	else if ($action == "importqdata")
		RWSActionImportQData();
	else if ($action == "getquiz")
		RWSActionGetQuiz();
	else if ($action == "exportqdata")
		RWSActionExportQData();
	else if ($action == "uploadfile")
		RWSActionUploadFile();
	else if ($action == "dnloadfile")
		RWSActionDnloadFile();
	else
		RWSServiceError("2050");
}
function RWSActionPHPInfo()
{
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	if (!is_siteadmin()) {
		RWSServiceError("2107");
	}
	phpinfo();
	exit;
}
function RWSActionServiceInfo()
{
	global $CFG;
	global $RWS_LDB_INFO;
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$is_logged_in = isloggedin();
	$is_admin = is_siteadmin();
	$self_url = RWSGetSelfURL(FALSE, TRUE);
	$version = "";
	$release = "";
	$requires = "";
	$latest = "";
	$version_file = RWSGetModulePath() . "/version.php";
	if (is_readable($version_file))
		include($version_file);
	if ($module) {
		if (!empty($module->version))
			$version = $module->version;
		if (!empty($module->rws_release))
			$release = $module->rws_release;
		if (!empty($module->requires))
			$requires = $module->requires;
		if (!empty($module->requires))
			$requires = $module->requires;
		if (!empty($module->rws_latest))
			$latest = $module->rws_latest;
	}
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_info>\r\n";
	if ($is_admin)
		echo "\t<description>Respondus 4.0 Web Service Extension For Moodle</description>\r\n";
	else
		echo "\t<description>(authentication required)</description>\r\n";
	if (!empty($version)) {
		echo "\t<module_version>";
		if ($behavior_version >= 2010042801) 
			echo utf8_encode(htmlspecialchars($version));
		else 
			echo "2009093000";
		echo "</module_version>\r\n";
	}
	else
		echo "\t<module_version />\r\n";
	if (!empty($release)) {
		echo "\t<module_release>";
		if ($behavior_version >= 2010042801) 
			echo utf8_encode(htmlspecialchars($release));
		else 
			echo "1.0.2";
		echo "</module_release>\r\n";
	}
	else
		echo "\t<module_release />\r\n";
	if ($behavior_version >= 2010042801) { 
		echo "\t<module_behavior>";
		echo utf8_encode(htmlspecialchars($behavior_version));
		echo "</module_behavior>\r\n";
	}
	if ($is_admin) {
		if (!empty($requires)) {
			echo "\t<module_requires>";
			echo utf8_encode(htmlspecialchars($requires));
			echo "</module_requires>\r\n";
		}
		else
			echo "\t<module_requires />\r\n";
	}
	else
		echo "\t<module_requires>(authentication required)</module_requires>\r\n";
	if ($is_admin) {
		if (!empty($latest)) {
			echo "\t<module_latest>";
			echo utf8_encode(htmlspecialchars($latest));
			echo "</module_latest>\r\n";
		}
		else
			echo "\t<module_latest />\r\n";
	}
	else
		echo "\t<module_latest>(authentication required)</module_latest>\r\n";
	if ($is_admin) {
		echo "\t<endpoint>";
		echo utf8_encode(htmlspecialchars($self_url));
		echo "</endpoint>\r\n";
	}
	else
		echo "\t<endpoint>(authentication required)</endpoint>\r\n";
	if ($is_admin) {
		echo "\t<whoami>";
		echo utf8_encode(htmlspecialchars(exec("whoami")));
		echo "</whoami>\r\n";
	}
	else
		echo "\t<whoami>(authentication required)</whoami>\r\n";
	if ($is_logged_in) {
		echo "\t<moodle_version>";
		echo utf8_encode(htmlspecialchars($CFG->version));
		echo "</moodle_version>\r\n";
	}
	else
		echo "\t<moodle_version>(authentication required)</moodle_version>\r\n";
	if ($is_logged_in) {
		echo "\t<moodle_release>";
		echo utf8_encode(htmlspecialchars($CFG->release));
		echo "</moodle_release>\r\n";
	}
	else
		echo "\t<moodle_release>(authentication required)</moodle_release>\r\n";
	if ($is_admin) {
		echo "\t<moodle_site_id>";
		echo utf8_encode(htmlspecialchars(SITEID));
		echo "</moodle_site_id>\r\n";
	}
	else
		echo "\t<moodle_site_id>(authentication required)</moodle_site_id>\r\n";
	if ($is_admin) {
		echo "\t<moodle_maintenance>";
		if (!empty($CFG->maintenance_enabled)
		  || file_exists($CFG->dataroot . "/" . SITEID . "/maintenance.html"))
			echo "yes";
		else
			echo "no";
		echo "</moodle_maintenance>\r\n";
	}
	else if ($behavior_version >= 2010063001) 
		echo "\t<moodle_maintenance>(authentication required)</moodle_maintenance>\r\n";
	else 
		echo "\t<moodle_maintenance>no</moodle_maintenance>\r\n";
	if ($is_admin) {
		$mod_names = get_list_of_plugins("mod");
		if ($mod_names && count($mod_names) > 0) {
			$mod_list = implode(",", $mod_names);
			echo "\t<moodle_module_types>";
			echo utf8_encode(htmlspecialchars(trim($mod_list)));
			echo "</moodle_module_types>\r\n";
		}
		else
			echo "\t<moodle_module_types />\r\n";
	}
	else
		echo "\t<moodle_module_types>(authentication required)</moodle_module_types>\r\n";
	$qtype_names = get_list_of_plugins("question/type");
	if (!$qtype_names)
		$qtype_names = array();
	$is_regexp = FALSE;
	if (count($qtype_names) > 0) {
		foreach ($qtype_names as $qn) {
			if (strcasecmp($qn, RWS_REGEXP) == 0) {
				$is_regexp = TRUE;
				break;
			}
		}
	}
	if ($is_admin) {
		if (count($qtype_names) > 0) {
			$qtype_list = implode(",", $qtype_names);
			echo "\t<moodle_question_types>";
			echo utf8_encode(htmlspecialchars(trim($qtype_list)));
			echo "</moodle_question_types>\r\n";
		}
		else
			echo "\t<moodle_question_types />\r\n";
	}
	else
		echo "\t<moodle_question_types>(authentication required)</moodle_question_types>\r\n";
	if ($is_logged_in) {
		echo "\t<cloze_regexp_support>";
		$path = "$CFG->dirroot/question/type/multianswer/questiontype.php";
		$data = file_get_contents($path);
		if ($data !== FALSE
		  && strpos($data, "ANSWER_REGEX_ANSWER_TYPE_REGEXP") !== FALSE) {
			if ($behavior_version >= 2010063001) { 
				if ($is_regexp)
					echo "yes";
				else
					echo "no";
			}
			else
				echo "yes";
		}
		else
			echo "no";
		echo "</cloze_regexp_support>\r\n";
	}
	else if ($behavior_version >= 2010063001) 
		echo "\t<cloze_regexp_support>(authentication required)</cloze_regexp_support>\r\n";
	else 
		echo "\t<cloze_regexp_support>no</cloze_regexp_support>\r\n";
	if ($is_logged_in) {
		echo "\t<ldb_module_detected>";
		if ($RWS_LDB_INFO->module_exists || $RWS_LDB_INFO->block_exists)
			echo "yes";
		else
			echo "no";
		echo "</ldb_module_detected>\r\n";
	}
	else if ($behavior_version >= 2010063001) 
		echo "\t<ldb_module_detected>(authentication required)</ldb_module_detected>\r\n";
	else 
		echo "\t<ldb_module_detected>no</ldb_module_detected>\r\n";
	if ($is_logged_in) {
		echo "\t<ldb_module_ok>";
		if ($RWS_LDB_INFO->module_ok || $RWS_LDB_INFO->block_ok)
			echo "yes";
		else
			echo "no";
		echo "</ldb_module_ok>\r\n";
	}
	else if ($behavior_version >= 2010063001) 
		echo "\t<ldb_module_ok>(authentication required)</ldb_module_ok>\r\n";
	else 
		echo "\t<ldb_module_ok>no</ldb_module_ok>\r\n";
	echo "</service_info>\r\n";
	exit;
}
function RWSFloatCompare($f1, $f2, $precision)
{
	if ($precision < 0)
		$precision = 0;
	$epsilon = 1 / pow(10, $precision);
	$diff = ($f1 - $f2);
	if (abs($diff) < $epsilon)
		return 0;
	else if ($diff < 0)
		return -1;
	else
		return 1;
}
function RWSDoubleToIEEE754($value)
{
	$test = unpack("C*", pack("S", 256));
	$chars = array_values(unpack("C*", pack("d", $value)));
	if($test[1] == 1) {
		$bytes = $chars;
	} else {
		$bytes = array_reverse($chars);
	}
	$binary = "";
	foreach ($bytes as $b)
		$binary .= pack("C", $b);
	return $binary;
}
function RWSIEEE754ToDouble($value)
{
	$test = unpack("C*", pack("S", 256));
	$bytes = array_values(unpack("C*", $value));
	if($test[1] == 1) {
		$chars = $bytes;
	} else {
		$chars = array_reverse($bytes);
	}
	$binary = "";
	foreach ($chars as $c)
		$binary .= pack("C", $c);
	$d = unpack("d", $binary);
	return $d[1];
}
function RWSGetCourseIdFromCategoryContext($context)
{
	global $DB;
	switch($context->contextlevel) {
	case CONTEXT_COURSE:
		$course_id = $context->instanceid;
		break;
	case CONTEXT_MODULE:
		$course_id = $DB->get_field("course_modules", "course",
			array("id" => $context->instanceid));
		if ($course_id === FALSE) {
			RWSServiceError("2111");
		}
		break;
	case CONTEXT_COURSECAT:
	case CONTEXT_SYSTEM:
		$course_id = SITEID;
		break;
	default: 
		RWSServiceError("2053");
	}
	return $course_id;
}
function RWSActionLogin()
{
	global $CFG;
	global $RWS_IGNORE_HTTPS_LOGIN;
	if (!$RWS_IGNORE_HTTPS_LOGIN) {
		if ($CFG->loginhttps && !$CFG->sslproxy) {
			if (!isset($_SERVER["HTTPS"])
			  || empty($_SERVER["HTTPS"])
			  || strcasecmp($_SERVER["HTTPS"], "off") == 0) {
				RWSServiceError("4001"); 
			}
		}
	}
	$username = RWSGetServiceOption("username");
	if ($username === FALSE || strlen($username) == 0)
		RWSServiceError("2054"); 
	$password = RWSGetServiceOption("password");
	if ($password === FALSE || strlen($password) == 0)
		RWSServiceError("2055"); 
	if (isloggedin())
		RWSServiceError("2056"); 
	RWSAuthenticateMoodleUser($username, $password, FALSE);
}
function RWSActionLogout()
{
	RWSCheckMoodleAuthentication();
	RWSLogoutMoodleUser();
}
function RWSPrelogoutCAS($cas_plugin)
{
	global $RWS_ENABLE_CAS_SSL3;
	if (isset($_SESSION['rwscas']['cookiejar']))
		$cookie_file = $_SESSION['rwscas']['cookiejar'];
	if (empty($cas_plugin->config->hostname)
	  || !$cas_plugin->config->logoutcas) {
		if (isset($cookie_file)) {
			if (file_exists($cookie_file))
				unlink($cookie_file);
			unset($_SESSION['rwscas']['cookiejar']);
		}
		unset($_SESSION['rwscas']);
		return;
	}
	list($v1, $v2, $v3) = explode(".", phpCAS::getVersion());
	$cas_plugin->connectCAS();
	$logout_url = phpCAS::getServerLogoutURL();
	$ch = curl_init();
	curl_setopt($ch, CURLOPT_URL, $logout_url);
	curl_setopt($ch, CURLOPT_HTTPGET, TRUE);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($ch, CURLOPT_FAILONERROR, TRUE);
	curl_setopt($ch, CURLOPT_TIMEOUT, 30); 
	curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_setopt($ch, CURLOPT_USERAGENT, "PHP");
	if (isset($cookie_file)) {
		curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file); 
		curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file);  
	}
	curl_exec($ch);
	curl_close($ch);
	if (isset($cookie_file)) {
		if (file_exists($cookie_file))
			unlink($cookie_file);
		unset($_SESSION['rwscas']['cookiejar']);
	}
	unset($_SESSION['rwscas']);
	session_unset();
	session_destroy();
}
function RWSActionCourseList()
{
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$courses = RWSGetMoodleUserModifyCourses();
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($courses) == 0) {
		echo "<courselist />\r\n";
		exit;
	}
	echo "<courselist>\r\n";
	foreach ($courses as $c) {
		echo "\t<course>\r\n";
		echo "\t\t<name>";
		echo utf8_encode(htmlspecialchars(trim($c->fullname)));
		echo "</name>\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($c->id)));
		echo "</id>\r\n";
		echo "\t</course>\r\n";
	}
	echo "</courselist>\r\n";
	exit;
}
function RWSActionSectionList()
{
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$param = RWSGetServiceOption("courseid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2057"); 
	$course_id = intval($param);
	$course = RWSCheckMoodleUserCourse($course_id);
	$sections = RWSGetMoodleUserVisibleSections($course_id);
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($sections) == 0) {
		echo "<sectionlist />\r\n";
		exit;
	}
	echo "<sectionlist>\r\n";
	if ($behavior_version < 2011020100) { 
		$format_name = get_generic_section_name($course->format, $sections[0]);
		$pos = strrpos($format_name, " ");
		if ($pos !== FALSE) 
			$format_name = substr($format_name, 0, $pos);
		echo "\t<format_name>";
		echo utf8_encode(htmlspecialchars(trim($format_name)));
		echo "</format_name>\r\n";
	}
	foreach ($sections as $s) {
		echo "\t<section>\r\n";
		if ($behavior_version >= 2011020100) { 
			$name = get_section_name($course, $s);
			echo "\t\t<name>";
			echo utf8_encode(htmlspecialchars($name));
			echo "</name>\r\n";
		}
		$summary = trim($s->summary);
		if (strlen($summary) > 0) {
			echo "\t\t<summary>";
			echo utf8_encode(htmlspecialchars($summary));
			echo "</summary>\r\n";
		}
		else
			echo "\t\t<summary />\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($s->id)));
		echo "</id>\r\n";
		echo "\t\t<relative_index>";
		echo utf8_encode(htmlspecialchars(trim($s->section)));
		echo "</relative_index>\r\n";
		echo "\t</section>\r\n";
	}
	echo "</sectionlist>\r\n";
	exit;
}
function RWSActionQuizList()
{
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("courseid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2057"); 
	$course_id = intval($param);
	RWSCheckMoodleUserCourse($course_id);
	$visible_quizzes = RWSGetMoodleUserVisibleQuizzes($course_id);
	if (count($visible_quizzes) > 0)
		$modify_quizzes = RWSGetMoodleUserModifyQuizzes($visible_quizzes);
	else
		$modify_quizzes = array();
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($visible_quizzes) == 0) {
		echo "<quizlist />\r\n";
		exit;
	}
	echo "<quizlist>\r\n";
	foreach ($visible_quizzes as $q) {
		echo "\t<quiz>\r\n";
		echo "\t\t<name>";
		echo utf8_encode(htmlspecialchars(trim($q->name)));
		echo "</name>\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($q->id)));
		echo "</id>\r\n";
		echo "\t\t<section_id>";
		echo utf8_encode(htmlspecialchars(trim($q->section)));
		echo "</section_id>\r\n";
		echo "\t\t<writable>";
		if (in_array($q, $modify_quizzes))
			echo "yes";
		else
			echo "no";
		echo "</writable>\r\n";
		echo "\t</quiz>\r\n";
	}
	echo "</quizlist>\r\n";
	exit;
}
function RWSActionQCatList()
{
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$requested_version = RWSGetServiceOption("version");
	if ($requested_version === FALSE || strlen($requested_version) == 0)
		$behavior_version = 2009093000;	
	else
		$behavior_version = intval($requested_version);
	$param = RWSGetServiceOption("courseid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2057"); 
	$course_id = intval($param);
	RWSCheckMoodleUserCourse($course_id);
	$qcats = RWSGetMoodleUserQCats($course_id);
	if ($behavior_version >= 2010063001) { 
		foreach ($qcats as $qc) {
			$context = get_context_instance_by_id($qc->contextid);
			$qc->course_id = RWSGetCourseIdFromCategoryContext($context);
		}
	}
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($qcats) == 0) {
		echo "<qcatlist />\r\n";
		exit;
	}
	echo "<qcatlist>\r\n";
	foreach ($qcats as $qc) {
		echo "\t<category>\r\n";
		echo "\t\t<name>";
		echo utf8_encode(htmlspecialchars(trim($qc->name)));
		echo "</name>\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($qc->id)));
		echo "</id>\r\n";
		if (!empty($qc->parent) && array_key_exists($qc->parent, $qcats)) {
			echo "\t\t<parent_id>";
			echo utf8_encode(htmlspecialchars(trim($qc->parent)));
			echo "</parent_id>\r\n";
		}
		if ($behavior_version >= 2010063001) { 
			if ($qc->course_id == SITEID) 
				echo "\t\t<system>yes</system>\r\n";
			else
				echo "\t\t<system>no</system>\r\n";
		}
		echo "\t</category>\r\n";
	}
	echo "</qcatlist>\r\n";
	exit;
}
function RWSActionAddQCat()
{
	global $DB;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("name");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2058"); 
	$qcat_name = trim(clean_text(strip_tags($param, "<lang><span>")));
	if (strlen($qcat_name) > 254) {
		RWSServiceError("2059");
	}
	$course_id = FALSE;
	$param = RWSGetServiceOption("courseid");
	if ($param !== FALSE && strlen($param) > 0)
		$course_id = intval($param);
	$parent_id = FALSE;
	$param = RWSGetServiceOption("parentid");
	if ($param !== FALSE && strlen($param) > 0)
		$parent_id = intval($param);
	if ($course_id === FALSE && $parent_id === FALSE) {
		RWSServiceError("2060");
	}
	else if ($course_id !== FALSE && $parent_id === FALSE) {
		RWSCheckMoodleUserCourse($course_id);
		$context = get_context_instance(CONTEXT_COURSE, $course_id);
		$parent_id = 0;
	}
	else if ($course_id === FALSE && $parent_id !== FALSE) {
		$record = $DB->get_record("question_categories",
		  array("id" => $parent_id));
		if ($record === FALSE) {
			RWSServiceError("2061");
		}
		$context = get_context_instance_by_id($record->contextid);
		$course_id = RWSGetCourseIdFromCategoryContext($context);
		RWSCheckMoodleUserCourse($course_id);
		if ($course_id == SITEID)
			$context = get_context_instance(CONTEXT_SYSTEM);
		else
			$context = get_context_instance(CONTEXT_COURSE, $course_id);
	}
	else 
	{
		RWSCheckMoodleUserCourse($course_id);
		$record = $DB->get_record("question_categories",
		  array("id" => $parent_id));
		if ($record === FALSE) {
			RWSServiceError("2061");
		}
		$context = get_context_instance_by_id($record->contextid);
		$qcat_course_id = RWSGetCourseIdFromCategoryContext($context);
		if ($qcat_course_id != $course_id) {
			if (is_siteadmin()) {
				if ($qcat_course_id != SITEID) {
					RWSServiceError("2110");
				}
				else
					$context = $sysctx;
			}
			else {
				RWSServiceError("2062");
			}
		}
		else
			$context = get_context_instance(CONTEXT_COURSE, $course_id);
	}
    $qcat = new stdClass();
    $qcat->parent = $parent_id;
    $qcat->contextid = $context->id;
    $qcat->name = $qcat_name;
    $qcat->info = "Created by Respondus";
	$qcat->infoformat = FORMAT_HTML;
    $qcat->sortorder = 999;
    $qcat->stamp = make_unique_id_code();
	$qcat_id = $DB->insert_record("question_categories", $qcat);
	rebuild_course_cache($course_id);
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<addqcat>\r\n";
	echo "\t<name>";
	echo utf8_encode(htmlspecialchars(trim($qcat_name)));
	echo "</name>\r\n";
	echo "\t<id>";
	echo utf8_encode(htmlspecialchars(trim($qcat_id)));
	echo "</id>\r\n";
	if ($parent_id != 0) {
		echo "\t<parent_id>";
		echo utf8_encode(htmlspecialchars(trim($parent_id)));
		echo "</parent_id>\r\n";
	}
	echo "</addqcat>\r\n";
	exit;
}
function RWSActionDeleteQCat()
{
	global $DB;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("qcatid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2064"); 
	$qcat_id = intval($param);
	$qcat = $DB->get_record("question_categories", array("id" => $qcat_id));
	if ($qcat === FALSE) 
		RWSServiceError("2065");
	$context = get_context_instance_by_id($qcat->contextid);
	$course_id = RWSGetCourseIdFromCategoryContext($context);
	RWSCheckMoodleUserCourse($course_id);
	question_can_delete_cat($qcat_id);
	if (RWSIsQuestionCategoryInUse($qcat_id)) {
		RWSServiceError("2066");
	}
	RWSDeleteQuestionCategory($qcat_id);
	rebuild_course_cache($course_id);
	RWSServiceStatus("1002"); 
}
function RWSActionDeleteQuiz()
{
	global $RWS_LDB_INFO;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("quizid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2067"); 
	$quiz_cmid = intval($param);
	$record = RWSCheckMoodleUserQuiz($quiz_cmid);
	$course_id = $record->course;
	RWSCheckMoodleUserCourse($course_id, TRUE);
	if (!quiz_delete_instance($record->instance)) {
		RWSServiceError("2068");
	}
	if (!delete_course_module($quiz_cmid)) {
		RWSServiceError("2069");
	}
	if (!delete_mod_from_section($quiz_cmid, $record->section)) {
		RWSServiceError("2070");
	}
	if ($RWS_LDB_INFO->module_ok)
		lockdown_delete_options($record->instance);
	else if ($RWS_LDB_INFO->block_ok)
		lockdown_delete_options($record->instance);
	rebuild_course_cache($course_id);
	RWSServiceStatus("1003"); 
}
function RWSActionAddQuiz()
{
	global $CFG;
	global $DB;
	global $RWS_LDB_INFO;
	global $USER;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("courseid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2057"); 
	$course_id = intval($param);
	$course = RWSCheckMoodleUserCourse($course_id, TRUE);
	$section_id = FALSE;
	$param = RWSGetServiceOption("sectionid");
	if ($param !== FALSE && strlen($param) > 0)
		$section_id = intval($param);
	if ($section_id === FALSE) {
		$section_relative = 0; 
	}
	else {
		$section = $DB->get_record("course_sections",
		  array("id" => $section_id));
		if ($section === FALSE)
			RWSServiceError("2071"); 
		if ($section->course != $course_id) {
			RWSServiceError("2072");
		}
		$section_relative = $section->section;
	}
	$param = RWSGetServiceOption("name");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2073"); 
	$quiz_name = trim(clean_text(strip_tags($param, "<lang><span>")));
	$sfile = RWSGetServiceOption("sfile");
	if ($sfile === FALSE) {
		$sname = RWSGetServiceOption("sname");
		$sdata = RWSGetServiceOption("sdata");
		$encoded = TRUE;
	}
	else {
		$sname = $sfile->filename;
		$sdata = $sfile->filedata;
		$encoded = FALSE;
	}
	$import = FALSE;
	if ($sdata !== FALSE && strlen($sdata) > 0) {
		if ($sname === FALSE || strlen($sname) == 0) {
			RWSServiceError("2075");
		}
		$sname = clean_filename($sname);
		$import = TRUE;
	}
	$modrec = $DB->get_record("modules", array("name" => "quiz"));
	if ($modrec === FALSE)
		RWSServiceError("2074"); 
    $quiz = new stdClass();
	$quiz->name = $quiz_name;
	$quiz->section = $section_relative;
	$quiz->course = $course_id;
	$quiz->coursemodule = 0;	
	$quiz->instance = 0;		
	$quiz->id = 0;				
	$quiz->modulename = $modrec->name;
	$quiz->module = $modrec->id;
	$quiz->groupmembersonly = 0;
	if (RWSFloatCompare($CFG->version, 2011120500.00, 2) >= 0) 
		$quiz->showdescription = 0; 
	$completion = new completion_info($course);
	if ($completion->is_enabled()) {
		$quiz->completion = COMPLETION_TRACKING_NONE;
		$quiz->completionview = COMPLETION_VIEW_NOT_REQUIRED;
		$quiz->completiongradeitemnumber = null;
		$quiz->completionexpected = 0; 
	}
	if ($CFG->enableavailability) {
		$quiz->availablefrom = 0; 
		$quiz->availableuntil = 0; 
		if ($quiz->availableuntil) { 
			$quiz->availableuntil = strtotime("23:59:59",
			  $quiz->availableuntil);
		}
		$quiz->showavailability = CONDITION_STUDENTVIEW_HIDE;
	}
	RWSSetQuizDefaults($quiz);
	if ($import)
		RWSImportQuizSettings($quiz, $sname, $sdata, $encoded);
	if (is_null($quiz->quizpassword) && !is_null($quiz->password))
		$quiz->quizpassword = $quiz->password;
	$quiz_cmid = add_course_module($quiz);
	if (!$quiz_cmid) 
		RWSServiceError("2077");
	$quiz->coursemodule = $quiz_cmid;
	$instance_id = quiz_add_instance($quiz); 
	if (!$instance_id || is_string($instance_id)) {
		RWSServiceError("2076");
	}
	$quiz->instance = $instance_id;
	$section_id_used = add_mod_to_section($quiz);
	if (!$section_id_used) 
		RWSServiceError("2078");
    $DB->set_field("course_modules", "section", $section_id_used,
	  array("id" => $quiz_cmid));
	if ($section_id !== FALSE && $section_id_used != $section_id) {
		RWSServiceError("2078");
	}
	RWSSaveLDBSettings($quiz);
    set_coursemodule_visible($quiz_cmid, $quiz->visible);
	if (isset($quiz->cmidnumber))  
		set_coursemodule_idnumber($quiz_cmid, $quiz->cmidnumber);
	RWSUpdateQuizGrades($quiz);
	if ($CFG->enableavailability) {
	}
	$event = new stdClass();
	$event->modulename = $quiz->modulename;
	$event->name = $quiz->name;
	$event->cmid = $quiz->coursemodule;
	$event->courseid = $quiz->course;
	$event->userid = $USER->id;
	events_trigger("mod_created", $event);
	rebuild_course_cache($course_id);
    grade_regrade_final_grades($course_id);
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<addquiz>\r\n";
	echo "\t<name>";
	echo utf8_encode(htmlspecialchars(trim($quiz->name)));
	echo "</name>\r\n";
	echo "\t<id>";
	echo utf8_encode(htmlspecialchars(trim($quiz_cmid)));
	echo "</id>\r\n";
	echo "\t<section_id>";
	echo utf8_encode(htmlspecialchars(trim($section_id_used)));
	echo "</section_id>\r\n";
	echo "\t<writable>yes</writable>\r\n";
	if ($RWS_LDB_INFO->module_exists || $RWS_LDB_INFO->block_exists) {
		if ($RWS_LDB_INFO->module_ok) {
			if ($RWS_LDB_INFO->put_settings_err) 
				echo "\t<service_warning>3003</service_warning>\r\n";
		} else if ($RWS_LDB_INFO->block_ok) {
			if ($RWS_LDB_INFO->put_settings_err) 
				echo "\t<service_warning>3003</service_warning>\r\n";
		} else { 
			echo "\t<service_warning>3001</service_warning>\r\n";
		}
	} else { 
		echo "\t<service_warning>3000</service_warning>\r\n";
	}
	echo "</addquiz>\r\n";
	exit;
}
function RWSActionUpdateQuiz()
{
	global $CFG;
	global $DB;
	global $RWS_LDB_INFO;
	global $USER;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("quizid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2067"); 
	$quiz_cmid = intval($param);
	$course_module = RWSCheckMoodleUserQuiz($quiz_cmid);
	$sfile = RWSGetServiceOption("sfile");
	if ($sfile === FALSE) {
		$sname = RWSGetServiceOption("sname");
		$sdata = RWSGetServiceOption("sdata");
		$encoded = TRUE;
	}
	else {
		$sname = $sfile->filename;
		$sdata = $sfile->filedata;
		$encoded = FALSE;
	}
	$import = FALSE;
	if ($sdata !== FALSE && strlen($sdata) > 0) {
		if ($sname === FALSE || strlen($sname) == 0) {
			RWSServiceError("2075");
		}
		$sname = clean_filename($sname);
		$import = TRUE;
	}
	$course_id = $course_module->course;
	$course = RWSCheckMoodleUserCourse($course_id, TRUE);
	$modrec = $DB->get_record("modules",
	  array("id" => $course_module->module));
    if ($modrec === FALSE) 
        RWSServiceError("2043");
	$quiz = $DB->get_record($modrec->name,
	  array("id" => $course_module->instance));
	if ($quiz === FALSE) 
        RWSServiceError("2044");
	$rename = FALSE;
	$param = RWSGetServiceOption("rename");
	if ($param !== FALSE && strlen($param) > 0) {
		$rename = trim(clean_text(strip_tags($param, "<lang><span>")));
		$quiz->name = $rename;
	}
	if ($rename === FALSE) {
		if ($sdata === FALSE || strlen($sdata) == 0)
			RWSServiceError("2080"); 
	}
	$section = $DB->get_record("course_sections",
	  array("id" => $course_module->section));
	if ($section === FALSE) {
        RWSServiceError("2079");
	}
    $quiz->coursemodule = $course_module->id;
    $quiz->section = $section->section;
    $quiz->visible = $course_module->visible;
    $quiz->cmidnumber = $course_module->idnumber;
    $quiz->groupmode = groups_get_activity_groupmode($course_module);
    $quiz->groupingid = $course_module->groupingid;
    $quiz->groupmembersonly = $course_module->groupmembersonly;
    $quiz->course = $course_id;
    $quiz->module = $modrec->id;
    $quiz->modulename = $modrec->name;
    $quiz->instance = $course_module->instance;
	if (RWSFloatCompare($CFG->version, 2011120500.00, 2) >= 0) 
		$quiz->showdescription = 0; 
	$completion = new completion_info($course);
	if ($completion->is_enabled()) {
		$quiz->completion = $course_module->completion;
		$quiz->completionview = $course_module->completionview;
		$quiz->completionexpected = $course_module->completionexpected;
		$quiz->completionusegrade =
		  is_null($course_module->completiongradeitemnumber) ? 0 : 1;
	}
	if ($CFG->enableavailability) {
		$quiz->availablefrom = $course_module->availablefrom;
		$quiz->availableuntil = $course_module->availableuntil;
		if ($quiz->availableuntil) { 
			$quiz->availableuntil = strtotime("23:59:59",
			  $quiz->availableuntil);
		}
		$quiz->showavailability = $course_module->showavailability;
	}
	$items = grade_item::fetch_all(array('itemtype'=>'mod',
	  'itemmodule'=>$quiz->modulename, 'iteminstance'=>$quiz->instance,
	  'courseid'=>$course_id));
	if ($items) {
        foreach ($items as $item) {
            if (!empty($item->outcomeid))
                $quiz->{'outcome_'.$item->outcomeid} = 1;
        }
        $gradecat = false;
        foreach ($items as $item) {
            if ($gradecat === false) {
                $gradecat = $item->categoryid;
                continue;
            }
            if ($gradecat != $item->categoryid) { 
                $gradecat = false;
                break;
            }
        }
        if ($gradecat !== false) 
            $quiz->gradecat = $gradecat;
    }
	if ($import)
		RWSImportQuizSettings($quiz, $sname, $sdata, $encoded);
	$DB->update_record("course_modules", $quiz);
	if (is_null($quiz->quizpassword) && !is_null($quiz->password))
		$quiz->quizpassword = $quiz->password;
	$result = quiz_update_instance($quiz);
	if (!$result || is_string($result)) {
		RWSServiceError("2081");
	}
	RWSSaveLDBSettings($quiz);
	set_coursemodule_visible($quiz_cmid, $quiz->visible);
	if (isset($quiz->cmidnumber))
		set_coursemodule_idnumber($quiz_cmid, $quiz->cmidnumber);
	RWSUpdateQuizGrades($quiz);
	if ($CFG->enableavailability) {
	}
	if ($completion->is_enabled() && !empty($quiz->completionunlocked))
		$completion->reset_all_state($quiz);
	$event = new stdClass();
	$event->modulename = $quiz->modulename;
	$event->name = $quiz->name;
	$event->cmid = $quiz->coursemodule;
	$event->courseid = $quiz->course;
	$event->userid = $USER->id;
	events_trigger("mod_updated", $event);
	rebuild_course_cache($course_id);
    grade_regrade_final_grades($course_id);
	if ($RWS_LDB_INFO->module_exists || $RWS_LDB_INFO->block_exists) {
		if ($RWS_LDB_INFO->module_ok) {
			if ($RWS_LDB_INFO->put_settings_err)
				RWSServiceWarning("3003"); 
		} else if ($RWS_LDB_INFO->block_ok) {
			if ($RWS_LDB_INFO->put_settings_err)
				RWSServiceWarning("3003"); 
		} else { 
			RWSServiceWarning("3001");
		}
	} else { 
		RWSServiceWarning("3000");
	}
	RWSServiceStatus("1004"); 
}
function RWSActionAddQList()
{
	global $DB;
	global $CFG;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("quizid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2067"); 
	$quiz_cmid = intval($param);
	$course_module = RWSCheckMoodleUserQuiz($quiz_cmid);
	$course_id = $course_module->course;
	RWSCheckMoodleUserCourse($course_id, TRUE);
	$qlist = RWSGetServiceOption("qlist");
	if ($qlist === FALSE || strlen($qlist) == 0)
		RWSServiceError("2082"); 
	$qids = explode(",", $qlist);
	if (count($qids) == 0 || strlen($qids[0]) == 0)
		RWSServiceError("2082");
	foreach ($qids as $key=>$value) {
		if ($value === FALSE || strlen($value) == 0)
			RWSServiceError("2108"); 
		$qids[$key] = intval($value);
	}
	$modrec = $DB->get_record("modules",
	  array("id" => $course_module->module));
    if ($modrec === FALSE) 
        RWSServiceError("2043");
	$quiz = $DB->get_record($modrec->name,
	  array("id" => $course_module->instance));
	if ($quiz === FALSE) 
        RWSServiceError("2044");
	if (!isset($quiz->instance))
		$quiz->instance = $quiz->id; 
	$errids = array();
	foreach ($qids as $id) {
		$rec = $DB->get_record("question", array("id" => $id));
		$ok = ($rec !== FALSE);
		if ($ok) {
			if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
				quiz_add_quiz_question($id, $quiz);
			}
			else {
				$ok = quiz_add_quiz_question($id, $quiz);
			}
		}
		if (!$ok)
			$errids[] = $id;
	}
	if (count($errids) > 0) {
		$errlist = implode(",", $errids);
		RWSServiceError("2083,$errlist");
	}
	if (count($errids) < count($qids))
		quiz_delete_previews($quiz);
	$quiz->grades = quiz_get_all_question_grades($quiz);
	$sum_grades = array_sum($quiz->grades);
	$DB->set_field("quiz", "sumgrades", $sum_grades, array("id" => $quiz->id));
	RWSServiceStatus("1005"); 
}
function RWSActionAddQRand()
{
	global $DB;
    global $USER;
	global $CFG;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("quizid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2067"); 
	$quiz_cmid = intval($param);
	$course_module = RWSCheckMoodleUserQuiz($quiz_cmid);
	$course_id = $course_module->course;
	RWSCheckMoodleUserCourse($course_id, TRUE);
	$modrec = $DB->get_record("modules",
	  array("id" => $course_module->module));
	if ($modrec === FALSE) 
		RWSServiceError("2043");
	$quiz = $DB->get_record($modrec->name,
	  array("id" => $course_module->instance));
	if ($quiz === FALSE) 
		RWSServiceError("2044");
	$param = RWSGetServiceOption("qcatid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2064"); 
	$qcat_id = intval($param);
	$qcat = $DB->get_record("question_categories", array("id" => $qcat_id));
	if ($qcat === FALSE) 
		RWSServiceError("2065");
	$context = get_context_instance_by_id($qcat->contextid);
	$qcat_course_id = RWSGetCourseIdFromCategoryContext($context);
	if ($qcat_course_id != $course_id) {
		if (is_siteadmin()) {
			if ($qcat_course_id != SITEID) {
				RWSServiceError("2109");
			}
		}
		else {
			RWSServiceError("2084");
		}
	}
	$param = RWSGetServiceOption("qcount");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2085"); 
	$qcount = intval($param);
	if ($qcount <= 0)
		RWSServiceError("2085");
	$param = RWSGetServiceOption("qgrade");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2086"); 
	$qgrade = round(floatval($param));
	if ($qgrade <= 0)
		RWSServiceError("2086");
	$modrec = $DB->get_record("modules",
	  array("id" => $course_module->module));
    if ($modrec === FALSE) 
        RWSServiceError("2043");
	$quiz = $DB->get_record($modrec->name,
	  array("id" => $course_module->instance));
	if ($quiz === FALSE) 
        RWSServiceError("2044");
	if (!isset($quiz->instance))
		$quiz->instance = $quiz->id; 
	$adderrs = 0;
	for ($i = 0; $i < $qcount; $i++) {
		$question = new stdClass();
		$question->qtype = RWS_RANDOM;
		$question->parent = 0;
		$question->hidden = 0;
		$question->length = 1;
		$question->questiontext = 1; 
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
			$randomqtype = question_bank::get_qtype("random");
			$question->name = $randomqtype->question_name($qcat,
			  !empty($question->questiontext));
		}
		else {
			$question->name = random_qtype::question_name($qcat,
			  !empty($question->questiontext));
		}
		$question->questiontextformat = FORMAT_HTML;
		$question->penalty = 0;
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) 
			$question->defaultmark = $qgrade;
		else
			$question->defaultgrade = $qgrade;
		$question->generalfeedback = "";
		$question->generalfeedbackformat = FORMAT_HTML;
		$question->category = $qcat->id;
		$question->stamp = make_unique_id_code();
		$question->createdby = $USER->id;
		$question->modifiedby = $USER->id;
		$question->timecreated = time();
		$question->timemodified = time();
		$question->id = $DB->insert_record("question", $question);
		$DB->set_field("question", "parent", $question->id,
		  array("id" => $question->id));
		$hash = question_hash($question);
		$DB->set_field("question", "version", $hash,
		  array("id" => $question->id));
		if (RWSFloatCompare($CFG->version, 2011070100, 2) >= 0) { 
			quiz_add_quiz_question($question->id, $quiz);
		}
		else {
			$ok = quiz_add_quiz_question($question->id, $quiz);
			if (!$ok) {
				$DB->delete_records("question", array("id" => $question->id));
				$adderrs++;
			}
		}
	}
	if ($adderrs > 0) {
		RWSServiceError("2087,$adderrs");
	}
	if ($adderrs < $qcount)
		quiz_delete_previews($quiz);
	$quiz->grades = quiz_get_all_question_grades($quiz);
	$sum_grades = array_sum($quiz->grades);
	$DB->set_field("quiz", "sumgrades", $sum_grades, array("id" => $quiz->id));
	RWSServiceStatus("1006"); 
}
function RWSActionImportQData()
{
	global $DB;
	global $USER;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("qcatid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2064"); 
	$qcat_id = intval($param);
	$qcat = $DB->get_record("question_categories", array("id" => $qcat_id));
	if ($qcat === FALSE) 
		RWSServiceError("2065");
	$context = get_context_instance_by_id($qcat->contextid);
	$course_id = RWSGetCourseIdFromCategoryContext($context);
	RWSCheckMoodleUserCourse($course_id);
	$qfile = RWSGetServiceOption("qfile");
	if ($qfile === FALSE) {
		$qname = RWSGetServiceOption("qname");
		$qdata = RWSGetServiceOption("qdata");
		$encoded = TRUE;
	}
	else {
		$qname = $qfile->filename;
		$qdata = $qfile->filedata;
		$encoded = FALSE;
	}
	if ($qname === FALSE || strlen($qname) == 0)
		RWSServiceError("2088"); 
	$qname = clean_filename($qname);
	if ($qdata === FALSE || strlen($qdata) == 0)
		RWSServiceError("2089"); 
	RWSAddToLog($course_id, "publish", "qcatid=$qcat_id");
	$dropped = 0;
	$badatts = 0;
	$qids = RWSImportQuestions(
	  $course_id, $qcat_id, $qname, $qdata, $encoded, $dropped, $badatts);
	$context = get_context_instance(CONTEXT_COURSE, $course_id);
	$contextid = $context->id;
	$component = "mod_respondusws";
	$filearea = "upload";
	$itemid = $USER->id;
	try {
		$fs = get_file_storage();
		if (!$fs->is_area_empty($contextid, $component, $filearea, $itemid, FALSE))	{
			$files = $fs->get_area_files($contextid, $component, $filearea, $itemid);
			foreach ($files as $file) {
				$old = time() - 60*60*24*1; 
				if ($file->get_timecreated() < $old)
					$file->delete();
			}
		}
	} catch (Exception $e) {
		RWSServiceError("2114");
	}
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<importqdata>\r\n";
	echo "\t<category_id>";
	echo utf8_encode(htmlspecialchars(trim($qcat_id)));
	echo "</category_id>\r\n";
	echo "\t<dropped>";
	echo utf8_encode(htmlspecialchars(trim($dropped)));
	echo "</dropped>\r\n";
	echo "\t<badatts>";
	echo utf8_encode(htmlspecialchars(trim($badatts)));
	echo "</badatts>\r\n";
	$qlist = implode(",", $qids);
	echo "\t<qlist>";
	echo utf8_encode(htmlspecialchars(trim($qlist)));
	echo "</qlist>\r\n";
	echo "</importqdata>\r\n";
	exit;
}
function RWSActionGetQuiz()
{
	global $CFG;
	global $DB;
	global $RWS_LDB_INFO;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$format = RWSGetServiceOption("format");
	if (strcasecmp($format, "base64") == 0)
		$want_base64 = TRUE;
	else if (strcasecmp($format, "binary") == 0)
		$want_base64 = FALSE;
	else
		RWSServiceError("2051"); 
	$param = RWSGetServiceOption("quizid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2067"); 
	$quiz_cmid = intval($param);
	$course_module = RWSCheckMoodleUserQuiz($quiz_cmid);
	$course_id = $course_module->course;
	$course = RWSCheckMoodleUserCourse($course_id, TRUE);
	$modrec = $DB->get_record("modules",
	  array("id" => $course_module->module));
    if ($modrec === FALSE) 
        RWSServiceError("2043");
	$quiz = $DB->get_record($modrec->name,
	  array("id" => $course_module->instance));
	if ($quiz === FALSE) 
        RWSServiceError("2044");
	$section = $DB->get_record("course_sections",
	  array("id" => $course_module->section));
	if ($section === FALSE) {
        RWSServiceError("2079");
	}
    $quiz->coursemodule = $course_module->id;
    $quiz->section = $section->section;
    $quiz->visible = $course_module->visible;
    $quiz->cmidnumber = $course_module->idnumber;
    $quiz->groupmode = groups_get_activity_groupmode($course_module);
    $quiz->groupingid = $course_module->groupingid;
    $quiz->groupmembersonly = $course_module->groupmembersonly;
    $quiz->course = $course_id;
    $quiz->module = $modrec->id;
    $quiz->modulename = $modrec->name;
    $quiz->instance = $course_module->instance;
	if (RWSFloatCompare($CFG->version, 2011120500.00, 2) >= 0) 
		$quiz->showdescription = $course_module->showdescription;
	$completion = new completion_info($course);
	if ($completion->is_enabled()) {
		$quiz->completion = $course_module->completion;
		$quiz->completionview = $course_module->completionview;
		$quiz->completionexpected = $course_module->completionexpected;
		$quiz->completionusegrade =
		  is_null($course_module->completiongradeitemnumber) ? 0 : 1;
	}
	if ($CFG->enableavailability) {
		$quiz->availablefrom = $course_module->availablefrom;
		$quiz->availableuntil = $course_module->availableuntil;
		if ($quiz->availableuntil) { 
			$quiz->availableuntil = strtotime("23:59:59",
			  $quiz->availableuntil);
		}
		$quiz->showavailability = $course_module->showavailability;
	}
	$items = grade_item::fetch_all(array('itemtype'=>'mod',
	  'itemmodule'=>$quiz->modulename, 'iteminstance'=>$quiz->instance,
	  'courseid'=>$course_id));
	if ($items) {
        foreach ($items as $item) {
            if (!empty($item->outcomeid))
                $quiz->{'outcome_'.$item->outcomeid} = 1;
        }
        $gradecat = false;
        foreach ($items as $item) {
            if ($gradecat === false) {
                $gradecat = $item->categoryid;
                continue;
            }
            if ($gradecat != $item->categoryid) { 
                $gradecat = false;
                break;
            }
        }
        if ($gradecat !== false) 
            $quiz->gradecat = $gradecat;
    }
	$sfile = "";
	$sdata = RWSExportQuizSettings($quiz, $sfile, $want_base64);
	if ($want_base64)
	{
		RWSResponseHeadersXml();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
		echo "<getquiz>\r\n";
		echo "\t<name>";
		echo utf8_encode(htmlspecialchars(trim($quiz->name)));
		echo "</name>\r\n";
		echo "\t<id>";
		echo utf8_encode(htmlspecialchars(trim($quiz_cmid)));
		echo "</id>\r\n";
		echo "\t<section_id>";
		echo utf8_encode(htmlspecialchars(trim($quiz->section)));
		echo "</section_id>\r\n";
		echo "\t<writable>yes</writable>\r\n";
		echo "\t<sfile>";
		echo utf8_encode(htmlspecialchars(trim($sfile)));
		echo "</sfile>\r\n";
		echo "\t<sdata>";
		echo utf8_encode(htmlspecialchars(trim($sdata)));
		echo "</sdata>\r\n";
		if ($RWS_LDB_INFO->module_exists || $RWS_LDB_INFO->block_exists) {
			if ($RWS_LDB_INFO->module_ok) {
				if ($RWS_LDB_INFO->get_settings_err) 
					echo "\t<service_warning>3002</service_warning>\r\n";
			} else if ($RWS_LDB_INFO->block_ok) {
				if ($RWS_LDB_INFO->get_settings_err) 
					echo "\t<service_warning>3002</service_warning>\r\n";
			} else { 
				echo "\t<service_warning>3001</service_warning>\r\n";
			}
		} else { 
			echo "\t<service_warning>3000</service_warning>\r\n";
		}
		echo "</getquiz>\r\n";
	}
	else 
	{
		$field = "name=\"" . htmlspecialchars(trim($quiz->name)) . "\"; ";
		$custom_header = $field;
		$field = "id=" . htmlspecialchars(trim($quiz_cmid)) . "; ";
		$custom_header .= $field;
		$field = "section_id=" . htmlspecialchars(trim($quiz->section)) . "; ";
		$custom_header .= $field;
		$field = "writable=yes";
		$custom_header .= $field;
		if ($RWS_LDB_INFO->module_exists || $RWS_LDB_INFO->block_exists) {
			if ($RWS_LDB_INFO->module_ok) {
				if ($RWS_LDB_INFO->get_settings_err) {
					$field = "; service_warning=3002";
					$custom_header .= $field;
				}
			} else if ($RWS_LDB_INFO->block_ok) {
				if ($RWS_LDB_INFO->get_settings_err) {
					$field = "; service_warning=3002";
					$custom_header .= $field;
				}
			} else { 
				$field = "; service_warning=3001";
				$custom_header .= $field;
			}
		} else { 
			$field = "; service_warning=3000";
			$custom_header .= $field;
		}
		header("X-GetQuiz: " . $custom_header);
		RWSResponseHeadersBinary($sfile, strlen($sdata));
		echo $sdata;
	}
	exit;
}
function RWSActionExportQData()
{
	global $DB;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$format = RWSGetServiceOption("format");
	if (strcasecmp($format, "base64") == 0)
		$want_base64 = TRUE;
	else if (strcasecmp($format, "binary") == 0)
		$want_base64 = FALSE;
	else
		RWSServiceError("2051"); 
	$quiz_cmid = FALSE;
	$param = RWSGetServiceOption("quizid");
	if ($param !== FALSE && strlen($param) > 0)
		$quiz_cmid = intval($param);
	$qcat_id = FALSE;
	$param = RWSGetServiceOption("qcatid");
	if ($param !== FALSE && strlen($param) > 0)
		$qcat_id = intval($param);
	if ($quiz_cmid === FALSE && $qcat_id === FALSE) {
		RWSServiceError("2090");
	}
	else if ($quiz_cmid !== FALSE && $qcat_id === FALSE) {
		$course_module = RWSCheckMoodleUserQuiz($quiz_cmid);
		$course_id = $course_module->course;
	}
	else if ($quiz_cmid === FALSE && $qcat_id !== FALSE) {
		$qcat = $DB->get_record("question_categories",
		  array("id" => $qcat_id));
		if ($qcat === FALSE) 
			RWSServiceError("2065");
		$context = get_context_instance_by_id($qcat->contextid);
		$course_id = RWSGetCourseIdFromCategoryContext($context);
	}
	else 
	{
		RWSServiceError("2091");
	}
	RWSCheckMoodleUserCourse($course_id);
	if ($quiz_cmid !== FALSE)
		RWSAddToLog($course_id, "retrieve", "quizid=$quiz_cmid");
	else 
		RWSAddToLog($course_id, "retrieve", "qcatid=$qcat_id");
	$qfile = "";
	$dropped = 0;
	$random = 0;
	if ($quiz_cmid !== FALSE) {
		$qdata = RWSExportQuizQuestions(
		  $quiz_cmid, $qfile, $dropped, $random, $want_base64);
	}
	else { 
		$qdata = RWSExportQCatQuestions(
		  $qcat_id, $qfile, $dropped, $want_base64);
	}
	if ($want_base64)
	{
		RWSResponseHeadersXml();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
		echo "<exportqdata>\r\n";
		if ($quiz_cmid !== FALSE) {
			echo "\t<quiz_id>";
			echo utf8_encode(htmlspecialchars(trim($quiz_cmid)));
			echo "</quiz_id>\r\n";
		}
		else 
		{
			echo "\t<category_id>";
			echo utf8_encode(htmlspecialchars(trim($qcat_id)));
			echo "</category_id>\r\n";
		}
		echo "\t<dropped>";
		echo utf8_encode(htmlspecialchars(trim($dropped)));
		echo "</dropped>\r\n";
		if ($quiz_cmid !== FALSE)	{
			echo "\t<random>";
			echo utf8_encode(htmlspecialchars(trim($random)));
			echo "</random>\r\n";
		}
		echo "\t<qfile>";
		echo utf8_encode(htmlspecialchars(trim($qfile)));
		echo "</qfile>\r\n";
		echo "\t<qdata>";
		echo utf8_encode(htmlspecialchars(trim($qdata)));
		echo "</qdata>\r\n";
		echo "</exportqdata>\r\n";
	}
	else 
	{
		if ($quiz_cmid !== FALSE)
			$field = "quiz_id=" . htmlspecialchars(trim($quiz_cmid)) . "; ";
		else 
			$field = "category_id=" . htmlspecialchars(trim($qcat_id)) . "; ";
		$custom_header = $field;
		$field = "dropped=" . htmlspecialchars(trim($dropped));
		$custom_header .= $field;
		if ($quiz_cmid !== FALSE) {
			$field = "; random=" . htmlspecialchars(trim($random));
			$custom_header .= $field;
		}
		header("X-ExportQData: " . $custom_header);
		RWSResponseHeadersBinary($qfile, strlen($qdata));
		echo $qdata;
	}
	exit;
}
function RWSActionUploadFile()
{
	global $CFG;
	global $USER;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("courseid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2057"); 
	if (strcasecmp($param, "site") == 0)
		$course_id = SITEID;
	else
		$course_id = intval($param);
	RWSCheckMoodleUserCourse($course_id);
	$file_folder = RWSGetServiceOption("folder");
	if ($file_folder === FALSE || strlen($file_folder) == 0)
		RWSServiceError("2092"); 
	$file_folder = clean_filename($file_folder);
	$file_binary = RWSGetServiceOption("filebinary");
	if ($file_binary === FALSE) {
		$file_name = RWSGetServiceOption("filename");
		$file_data = RWSGetServiceOption("filedata");
		$encoded = TRUE;
	}
	else {
		$file_name = $file_binary->filename;
		$file_data = $file_binary->filedata;
		$encoded = FALSE;
	}
	if ($file_name === FALSE || strlen($file_name) == 0)
		RWSServiceError("2093"); 
	$file_name = clean_filename($file_name);
	if ($file_data === FALSE || strlen($file_data) == 0)
		RWSServiceError("2094"); 
	if ($encoded) {
		$decoded_data = base64_decode($file_data);
		if ($decoded_data === FALSE) {
			RWSServiceError("2097");
		}
	}
	else { 
		$decoded_data = $file_data;
	}
	$context = get_context_instance(CONTEXT_COURSE, $course_id);
	$contextid = $context->id;
	$component = "mod_respondusws";
	$filearea = "upload";
	$itemid = $USER->id;
	$filepath = "/$file_folder/";
	$filename = $file_name;
	$fileinfo = array(
	  "contextid" => $contextid, "component" => $component,
	  "filearea" => $filearea, "itemid" => $itemid,
	  "filepath" => $filepath, "filename" => $filename
	  );
	$course_relpath = "$file_folder/$file_name";
	try {
		$fs = get_file_storage();
		$file_exists = $fs->file_exists(
		  $contextid, $component, $filearea, $itemid, $filepath, $filename
		  );
		if ($file_exists) {
			RWSServiceError("2096,$course_relpath");
		}
		if (!$fs->create_file_from_string($fileinfo, $decoded_data))
			RWSServiceError("2098"); 
	} catch (Exception $e) {
		RWSServiceError("2098"); 
	}
	RWSResponseHeadersXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<uploadfile>\r\n";
	echo "\t<course_subpath>";
	echo utf8_encode(htmlspecialchars(trim($course_relpath)));
	echo "</course_subpath>\r\n";
	echo "</uploadfile>\r\n";
	exit;
}
function RWSActionDnloadFile()
{
	global $CFG;
	global $USER;
	RWSCheckMoodleAuthentication();
	RWSCheckMoodleUserWebService();
	RWSCheckMoodleMaintenance();
	$param = RWSGetServiceOption("courseid");
	if ($param === FALSE || strlen($param) == 0)
		RWSServiceError("2057"); 
	if (strcasecmp($param, "site") == 0)
		$course_id = SITEID;
	else
		$course_id = intval($param);
	$course = RWSCheckMoodleUserCourse($course_id);
	$format = RWSGetServiceOption("format");
	if (strcasecmp($format, "base64") == 0)
		$want_base64 = TRUE;
	else if (strcasecmp($format, "binary") == 0)
		$want_base64 = FALSE;
	else
		RWSServiceError("2051"); 
	$file_ref = RWSGetServiceOption("fileref");
	if ($file_ref === FALSE || strlen($file_ref) == 0)
		RWSServiceError("2099"); 
	$start = stripos($file_ref, "/pluginfile.php");
	if ($start !== FALSE) {
		$start = strpos($file_ref, "/", $start+1);
		if ($start === FALSE)
			RWSServiceError("2100"); 
		$path = substr($file_ref, $start);
		$parts = explode("/", ltrim($path, '/'));
		if (count($parts) < 5)
			RWSServiceError("2100"); 
		$contextid = intval(array_shift($parts));
		$component = clean_param(array_shift($parts), PARAM_SAFEDIR);
		$filearea = clean_param(array_shift($parts), PARAM_SAFEDIR);
		$itemid = intval(array_shift($parts));
		$filename = clean_filename(array_pop($parts));
		$filepath = "/";
		if (count($parts) > 0)
			$filepath = "/". implode("/", $parts) . "/";
		try {
			$fs = get_file_storage();
			$file_exists = $fs->file_exists(
			  $contextid, $component, $filearea, $itemid, $filepath, $filename
			  );
			if (!$file_exists)
				RWSServiceError("2100"); 
			$file = $fs->get_file(
			  $contextid, $component, $filearea, $itemid, $filepath, $filename
			  );
			if ($file === FALSE)
				RWSServiceError("2101"); 
			$file_data = $file->get_content();
			$file_name = $filename;
		} catch (Exception $e) {
			RWSServiceError("2101"); 
		}
	} else {
		$start = stripos($file_ref, "/draftfile.php");
		if ($start !== FALSE) {
			$start = strpos($file_ref, "/", $start+1);
			if ($start === FALSE)
				RWSServiceError("2100"); 
			$path = substr($file_ref, $start);
			$parts = explode("/", ltrim($path, '/'));
			if (count($parts) < 5)
				RWSServiceError("2100"); 
			$contextid = intval(array_shift($parts));
			$context = get_context_instance_by_id($contextid);
			if ($context->contextlevel != CONTEXT_USER)
				RWSServiceError("2100"); 
			$component = array_shift($parts);
			if ($component !== "user")
				RWSServiceError("2100"); 
			$filearea = array_shift($parts);
			if ($filearea !== "draft")
				RWSServiceError("2100"); 
			$draftid = intval(array_shift($parts));
			$relpath = implode("/", $parts);
			$filename = array_pop($parts);
			$fullpath = "/$contextid/user/draft/$draftid/$relpath";
			try {
				$fs = get_file_storage();
				$file = $fs->get_file_by_hash(sha1($fullpath));
				if ($file === FALSE)
					RWSServiceError("2101"); 
				if ($file->get_filename() == ".")
					RWSServiceError("2101"); 
				$file_data = $file->get_content();
				$file_name = $filename;
			} catch (Exception $e) {
				RWSServiceError("2101"); 
			}
		} else {
			$start = stripos($file_ref, "/file.php");
			if ($start !== FALSE) {
				$start = strpos($file_ref, "/", $start+1);
				if ($start === FALSE)
					RWSServiceError("2100"); 
				$path = substr($file_ref, $start);
				$parts = explode("/", ltrim($path, '/'));
				if (count($parts) < 1)
					RWSServiceError("2100"); 
				if ($course->legacyfiles != 2)
					RWSServiceError("2113"); 
				$courseid = intval(array_shift($parts));
				if ($courseid != $course_id)
					RWSServiceError("2100"); 
				$context = get_context_instance(CONTEXT_COURSE, $course_id);
				$contextid = $context->id;
				$relpath = implode("/", $parts);
				$filename = array_pop($parts);
				$fullpath = "/$contextid/course/legacy/0/$relpath";
				try {
					$fs = get_file_storage();
					$file = $fs->get_file_by_hash(sha1($fullpath));
					if ($file === FALSE)
						RWSServiceError("2101"); 
					$file_data = $file->get_content();
					$file_name = $filename;
				} catch (Exception $e) {
					RWSServiceError("2101"); 
				}
			} else {
				RWSServiceError("2100"); 
			}
		}
	}
	if ($want_base64)
	{
		RWSResponseHeadersXml();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
		echo "<dnloadfile>\r\n";
		echo "\t<filename>";
		echo utf8_encode(htmlspecialchars(trim($file_name)));
		echo "</filename>\r\n";
		$encoded_data = base64_encode($file_data);
		echo "\t<filedata>";
		echo utf8_encode(htmlspecialchars(trim($encoded_data)));
		echo "</filedata>\r\n";
		echo "</dnloadfile>\r\n";
	}
	else 
	{
		RWSResponseHeadersBinary($file_name, strlen($file_data));
		echo $file_data;
	}
	exit;
}
function RWSErrorLog($msg)
{
	$entry = date("m-d-Y H:i:s") . " - " . $msg . "\r\n";
	$path = RWSGetTempPath();
    $handle = fopen("$path/rwserr.log", "ab");
	if ($handle !== FALSE) {
		fwrite($handle, $entry, strlen($entry));
		fclose($handle);
	}
}
function RWSExceptionHandler($ex)
{
	abort_all_db_transactions();
	$info = get_exception_info($ex);
	$msg  = "\r\n-- Exception occurred --";
	$msg .= "\r\nmessage: $info->message";
	$msg .= "\r\nerrorcode: $info->errorcode";
	$msg .= "\r\nbacktrace: $info->backtrace";
	$msg .= "\r\nlink: $info->link";
	$msg .= "\r\nmoreinfourl: $info->moreinfourl";
	$msg .= "\r\na: $info->a";
	$msg .= "\r\ndebuginfo: $info->debuginfo\r\n";
	RWSErrorLog($msg);
	RWSErrorLog("\r\nstacktrace: ".$ex->getTraceAsString());
	RWSServiceError("2112,$info->errorcode");
}

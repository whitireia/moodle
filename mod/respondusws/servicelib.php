<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
$RWSIHLOG = FALSE;
$RWSECAS = FALSE;
$RWSESL3 = FALSE; 
$RWSSRURL = "";
$RWSCRURL = "";
$RWSPFNAME = "partiallycorrectfeedbackformat";
define("NO_DEBUG_DISPLAY", true);
$r_mcfg = dirname(dirname(dirname(__FILE__))) . "/config.php";
if (is_readable($r_mcfg))
    require_once($r_mcfg);
else  
	RWSSErr("2002");
defined("MOODLE_INTERNAL") || die();
$r_sf = TRUE;
if ($r_sf)
	$r_sf = is_readable("$CFG->dirroot/version.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/moodlelib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/datalib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/filelib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/completionlib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/conditionlib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/eventslib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/weblib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/accesslib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/dmllib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/ddllib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/questionlib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/grouplib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->libdir/gradelib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->dirroot/mod/quiz/lib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->dirroot/course/lib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->dirroot/mod/quiz/editlib.php");
if ($r_sf)
	$r_sf = is_readable("$CFG->dirroot/question/editlib.php");
if ($r_sf && $RWSECAS)
	$r_sf = is_readable("$CFG->dirroot/auth/cas/CAS/CAS.php");
if (!$r_sf) {
	RWSSErr("2003");
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
if ($RWSECAS)
	require_once("$CFG->dirroot/auth/cas/CAS/CAS.php");
$RWSLB = new stdClass();
$RWSLB->atts = 0; 
$RWSLB->revs = 0; 
$RWSLB->pw = ""; 
$RWSLB->mok = FALSE; 
$RWSLB->bok = FALSE; 
$RWSLB->gerr = FALSE; 
$RWSLB->perr = FALSE; 
$RWSLB->mex = 
  is_readable("$CFG->dirroot/mod/lockdown/locklib.php");
$RWSLB->bex = 
  is_readable("$CFG->dirroot/blocks/lockdownbrowser/locklib.php");
if ($RWSLB->mex) {
	include_once("$CFG->dirroot/mod/lockdown/locklib.php");
	$RWSLB->mok = lockdown_module_status();
} else if ($RWSLB->bex) {
	include_once("$CFG->dirroot/blocks/lockdownbrowser/locklib.php");
	$RWSLB->bok = (!empty($CFG->customscripts)
	  && is_readable("$CFG->customscripts/mod/quiz/attempt.php")
	  && $DB->get_manager()->table_exists("block_lockdownbrowser_tokens")
	  && $DB->count_records("block_lockdownbrowser_tokens") > 0);
}
define("RWSQAD", 1);
define("RWSRRE", 1*0x1041);
define("RWSRSC", 2*0x1041);
define("RWSRFE", 4*0x1041);
define("RWSRAN", 8*0x1041);
define("RWSRSO", 16*0x1041);
define("RWSRGE", 32*0x1041);
define("RWSROV", 1*0x4440000);
define("RWSRIM", 0x3c003f);
define("RWSROP", 0x3c00fc0);
define("RWSRCL", 0x3c03f000);
define("RWSRDU", 0x10000);
define("RWSRIA", 0x01000);
define("RWSRLA", 0x00100);
define("RWSRAF", 0x00010);
define("RWSUIN", 0);
define("RWSUNO", 3);
define("RWSOPT", 0);
define("RWSGRD", 1);
define("RWSATT", "rwsatt");
define("RWSRSV", "rwsrsv");
define("RWSUNK", "rwsunk");
define("RWSSHA", "shortanswer");
define("RWSTRF", "truefalse");
define("RWSMAN", "multianswer");
define("RWSNUM", "numerical");
define("RWSMCH", "multichoice");
define("RWSCAL", "calculated");
define("RWSMAT", "match");
define("RWSDES", "description");
define("RWSESS", "essay");
define("RWSRND", "random");
define("RWSRSM", "randomsamatch");
define("RWSCSI", "calculatedsimple");
define("RWSCMU", "calculatedmulti");
define("RWSCAS", "cas");
define("RWSRXP", "regexp");
function RWSRHCom()
{
	header("Cache-Control: private, must-revalidate"); 
	header("Expires: -1");
	header("Pragma: no-cache");
}
function RWSRHXml()
{
	RWSRHCom();
	header("Content-Type: text/xml");
}
function RWSRHBin($r_fn, $r_clen)
{
	RWSRHCom();
	header("Content-Type: application/octet-stream");
	header("Content-Length: " . $r_clen);
	header(
	  "Content-Disposition: attachment; filename=\""
	  . htmlspecialchars(trim($r_fn)) . "\""
	  );
	header("Content-Transfer-Encoding: binary");
}
function RWSSWarn($r_wm="")
{
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_warning>";
	if (!empty($r_wm))
		echo utf8_encode(htmlspecialchars($r_wm));
	else
		echo "3004"; 
	echo "</service_warning>\r\n";
	exit;
}
function RWSSStat($r_sm="")
{
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_status>";
	if (!empty($r_sm))
		echo utf8_encode(htmlspecialchars($r_sm));
	else
		echo "1007"; 
	echo "</service_status>\r\n";
	exit;
}
function RWSSErr($r_errm="")
{
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_error>";
	if (!empty($r_errm))
		echo utf8_encode(htmlspecialchars($r_errm));
	else
		echo "2004"; 
	echo "</service_error>\r\n";
	exit;
}
function RWSLMUser()
{
    global $USER;
	global $CFG;
	global $RWSECAS;
	if (!$RWSECAS) {
		require_logout();
		RWSSStat("1001"); 
	}
	if (RWSFCmp($CFG->version, 2010122500, 2) >= 0) {
		$r_prms = $USER;
		if (isloggedin()) {
			$r_aus = get_enabled_auth_plugins();
			foreach ($r_aus as $r_aun) {
				$r_aup = get_auth_plugin($r_aun);
				if (strcasecmp($r_aup->authtype, RWSCAS) == 0) {
					$r_csp = $r_aup;
					RWSPLOCas($r_csp);
				} else {
					$r_aup->prelogout_hook();
				}
			}
		}
		events_trigger('user_logout', $r_prms);
		session_get_instance()->terminate_current();
		unset($r_prms);
	} else {
		RWSSErr("2006,$CFG->version,2010122500");
	}
	RWSSStat("1001"); 
}
function RWSCMBVer()
{
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0) {
		return;
	}
	$r_bv = intval($r_rv);
	if ($r_bv == 2009093000		
	  || $r_bv == 2010042801	
	  || $r_bv == 2010063001	
	  || $r_bv == 2010063002	
	  || $r_bv == 2010063003	
	  || $r_bv == 2010063004	
	  || $r_bv == 2010063005	
	  || $r_bv == 2011020100	
	  || $r_bv == 2011040400	
	  || $r_bv == 2011071500	
	  || $r_bv == 2011080100	
	  || $r_bv == 2011102500	
	  || $r_bv == 2011121500	
	  ) {
		return; 
	}
	RWSSErr("2106");
}
function RWSCMVer()
{
	global $CFG;
	$r_req = "";
	$r_vf = RWSGMPath() . "/version.php";
	if (is_readable($r_vf))
		include($r_vf);
	if ($module) {
		if (!empty($module->requires))
			$r_req = $module->requires;
	}
	if (empty($r_req)) {
		RWSSErr("2005");
	}
	$r_res = RWSFCmp($CFG->version, $r_req, 2);
	if ($r_res == -1) {
		RWSSErr("2006,$CFG->version,$r_req");
	}
	else if ($r_res == 1) {
	}
}
function RWSCMInst()
{
	global $DB;
	$r_dbm = $DB->get_manager();
	if ($r_dbm->table_exists("respondusws"))
		$r_ins = $DB->get_records("respondusws", array("course" => SITEID));
	else
		$r_ins = array();
	$r_ok = (count($r_ins) == 1);
	if (!$r_ok) {
		RWSSErr("2007");
	}
}
function RWSATLog($r_cid, $r_ac, $r_inf="")
{
	add_to_log($r_cid, "respondusws", $r_ac,
	 "index.php?id=$r_cid", $r_inf);
}
function RWSGMPath()
{
	$r_mp = dirname(__FILE__); 
	if (DIRECTORY_SEPARATOR != '/') 
	  $r_mp = str_replace('\\', '/', $r_mp);
	return $r_mp;
}
function RWSGTPath()
{
	global $CFG;
	if (RWSFCmp($CFG->version, 2011120500.00, 2) >= 0) { 
		if (isset($CFG->tempdir))
			$r_tp = "$CFG->tempdir";
		else
			$r_tp = "$CFG->dataroot/temp";
	}
	else { 
		$r_tp = "$CFG->dataroot/temp";
	}
	return $r_tp;
}
function RWSGSUrl($r_fhts, $r_include_query)
{
	$r_hs = $r_fhts;
	if (!$r_hs) {
		$r_hs = (isset($_SERVER['HTTPS'])
		  && !empty($_SERVER['HTTPS'])
		  && strcasecmp($_SERVER['HTTPS'], "off") != 0);
	}
	if ($r_hs)
		$r_su = 'https://';
	else
		$r_su = 'http://';
	if (empty($_SERVER['HTTP_X_FORWARDED_SERVER'])) {
		if (empty($_SERVER['SERVER_NAME'])) {
			$r_su .= $_SERVER['HTTP_HOST'];
		} else {
			$r_su .= $_SERVER['SERVER_NAME'];
		}
	} else {
		$r_su .= $_SERVER['HTTP_X_FORWARDED_SERVER'];
	}
	if (strpos($r_su, ":") === FALSE) {
		if (($r_hs && $_SERVER['SERVER_PORT'] != 443)
		  || (!$r_hs && $_SERVER['SERVER_PORT'] != 80)) {
			$r_su .= ':';
			$r_su .= $_SERVER['SERVER_PORT'];
		}
	}
	if (!isset($_SERVER['REQUEST_URI'])) {
		$_SERVER['REQUEST_URI'] = $_SERVER['SCRIPT_NAME'];
		if (isset($_SERVER['QUERY_STRING'])) {
			$_SERVER['REQUEST_URI'] .= '?';
			$_SERVER['REQUEST_URI'] .= $_SERVER['QUERY_STRING'];
		}
	}
	$r_bu = explode("?", $_SERVER['REQUEST_URI'], 2);
	$r_su .= $r_bu[0];
	if ($r_include_query) {
		$r_qry = "";
		if ($_GET) {
			$r_pms = array();
			foreach ($_GET as $r_k => $r_val)
				$r_pms[] = urlencode($r_k) . "=" . urlencode($r_val);
			$r_qry = join("&", $r_pms);
		}
		if (strlen($r_qry) > 0)
			$r_su .= "?" . $r_qry;
	}
	return $r_su;
}
function RWSAMUser($r_usrn, $r_pw, $r_csf)
{
	global $RWSECAS;
	if ($RWSECAS)
		RWSPLICas($r_usrn, $r_pw, $r_csf);
	$r_usr = authenticate_user_login($r_usrn, $r_pw);
	if ($r_usr)
		complete_user_login($r_usr);
	if (isloggedin()) {
		RWSSStat("1000"); 
	} else {
		if ($RWSECAS) {
			if (isset($_SESSION['rwscas']['cookiejar'])) {
				$r_ckf = $_SESSION['rwscas']['cookiejar'];
				if (file_exists($r_ckf))
					unlink($r_ckf);
				unset($_SESSION['rwscas']['cookiejar']); 
			}
			unset($_SESSION['rwscas']);
		}
		RWSSErr("2008"); 
	}
}
function RWSPLICas($r_usrn, $r_pw, $r_csf)
{
	global $RWSESL3;
	global $RWSSRURL;
	global $RWSCRURL;
	if ($r_csf)
		return;
	$r_aus = get_enabled_auth_plugins();
    foreach ($r_aus as $r_aun) {
		$r_aup = get_auth_plugin($r_aun);
		if (strcasecmp($r_aup->authtype, RWSCAS) == 0) {
			$r_csp = $r_aup;
			break;
		}
	}
	if (!isset($r_csp))
		return;
	if (empty($r_csp->config->hostname))
		return;
	if ($r_csp->config->multiauth) {
		$r_auc = RWSGSOpt("authCAS");
		if ($r_auc === FALSE || strlen($r_auc) == 0)
			$r_auc = "CAS";
		if (strcasecmp($r_auc, "CAS") != 0)
			return;
	}
	list($r_v1, $r_v2, $r_v3) = explode(".", phpCAS::getVersion());
	$r_csp->connectCAS();
	if (phpCAS::isSessionAuthenticated())
		return;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		unset($r_bv);
	else
		$r_bv = intval($r_rv);
	if (strlen($RWSCRURL) > 0)
		$r_svu = $RWSCRURL;
	else
		$r_svu = RWSGSUrl(FALSE, FALSE);
	$r_svu .= "?rwscas=1"; 
	if (isset($r_bv)) {
		$r_svu .= "&version=";
		$r_svu .= urlencode($r_bv);
	}
	if (isset($r_usrn)) {
		$r_svu .= "&rwsuser=";
		$r_svu .= urlencode($r_usrn);
	}
	if (isset($r_pw)) {
		$r_svu .= "&rwspass=";
		$r_svu .= urlencode($r_pw);
	}
	phpCAS::setFixedServiceURL($r_svu);
	if ($r_csp->config->proxycas) {
		if (strlen($RWSCRURL) > 0)
			$r_cbu = $RWSCRURL;
		else
			$r_cbu = RWSGSUrl(TRUE, FALSE);
		$r_cbu .= "?rwscas=2";  
		if (isset($r_bv)) {
			$r_cbu .= "&version=";
			$r_cbu .= urlencode($r_bv);
		}
		if (isset($r_usrn)) {
			$r_cbu .= "&rwsuser=";
			$r_cbu .= urlencode($r_usrn);
		}
		if (isset($r_pw)) {
			$r_cbu .= "&rwspass=";
			$r_cbu .= urlencode($r_pw);
		}
			phpCAS::setFixedCallbackURL($r_cbu);
	}
	$r_tpp = RWSGTPath();
	if ($r_tpp !== FALSE) {
		$r_ckf = tempnam($r_tpp, "rws");
		if ($r_ckf !== FALSE)
			$_SESSION['rwscas']['cookiejar'] = $r_ckf;
	}
	$r_liu = phpCAS::getServerLoginURL();
	$r_ch = curl_init();
	curl_setopt($r_ch, CURLOPT_URL, $r_liu);
	curl_setopt($r_ch, CURLOPT_HTTPGET, TRUE);
	curl_setopt($r_ch, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($r_ch, CURLOPT_HEADER, TRUE);
	curl_setopt($r_ch, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($r_ch, CURLOPT_FAILONERROR, TRUE);
	curl_setopt($r_ch, CURLOPT_TIMEOUT, 30); 
	curl_setopt($r_ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	curl_setopt($r_ch, CURLOPT_SSL_VERIFYPEER, FALSE);
	if ($RWSESL3)
		curl_setopt($r_ch, CURLOPT_SSLVERSION, 3);
	curl_setopt($r_ch, CURLOPT_USERAGENT, "PHP");
	if (isset($r_ckf)) {
		curl_setopt($r_ch, CURLOPT_COOKIEFILE, $r_ckf); 
		curl_setopt($r_ch, CURLOPT_COOKIEJAR, $r_ckf);  
	}
	$r_rsp = curl_exec($r_ch);
	if ($r_rsp === FALSE) {
		curl_close($r_ch);
		return;
	}
	$r_p = 0;
	while (stripos($r_rsp, "HTTP/", $r_p) === 0) {
		$r_p = stripos($r_rsp, "\r\n\r\n", $r_p);
		if ($r_p === FALSE)
			break;
		$r_p += 4;
	}
	if ($r_p === 0) {
		$r_hdrs = "";
		$r_hset = "";
		$r_bdy = $r_rsp;
	} else if ($r_p === FALSE) {
		$r_hdrs = $r_rsp;
		$r_hset = explode("\r\n\r\n", $r_hdrs);
		$r_bdy = "";
	} else {
		$r_hdrs = substr($r_rsp, 0, $r_p - 4);
		$r_hset = explode("\r\n\r\n", $r_hdrs);
		$r_bdy = substr($r_rsp, $r_p);
	}
	$r_ac = "";
	$r_lt = "";
	$r_evt_id = "";
	$r_sub = "";
	$r_p = 0;
	$r_l = strlen($r_bdy);
	$r_st = stripos($r_bdy, "<form ");
	if ($r_st !== FALSE) {
		$r_end = stripos($r_bdy, ">", $r_st);
		if ($r_end === FALSE)
			$r_end = $r_l;
		$r_p = stripos($r_bdy, "action=\"", $r_st);
		if ($r_p === FALSE || $r_p > $r_end)
			$r_p = stripos($r_bdy, "action = \"", $r_st);
		if ($r_p === FALSE || $r_p > $r_end)
			$r_p = stripos($r_bdy, "action=\'", $r_st);
		if ($r_p === FALSE || $r_p > $r_end)
			$r_p = stripos($r_bdy, "action = \'", $r_st);
		if ($r_p !== FALSE && $r_p < $r_end) {
			while ($r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
				$r_p++;
			$r_p++;
			$r_st = $r_p;
			while ($r_p < $r_end && $r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
				$r_p++;
			$r_end = $r_p;
			$r_ac = substr($r_bdy, $r_st, $r_end - $r_st);
		}
	}
	while (strlen($r_lt) == 0
	  || strlen($r_evt_id) == 0
	  || strlen($r_sub) == 0) {
		$r_nx = stripos($r_bdy, "<input ", $r_p);
		if ($r_nx === FALSE)
			break;
		$r_st = $r_nx;
		$r_end = stripos($r_bdy, ">", $r_st);
		if ($r_end === FALSE)
			$r_end = $r_l;
		if (strlen($r_lt) == 0) {
			$r_st = stripos($r_bdy, "name=\"lt\"", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name = \"lt\"", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name=\'lt\'", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name = \'lt\'", $r_nx);
			if ($r_st !== FALSE && $r_st < $r_end) {
				$r_p = stripos($r_bdy, "value=\"", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value = \"", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value=\'", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value = \'", $r_st);
				if ($r_p !== FALSE && $r_p < $r_end) {
					while ($r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
						$r_p++;
					$r_p++;
					$r_st = $r_p;
					while ($r_p < $r_end && $r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
						$r_p++;
					$r_end = $r_p;
					$r_lt = substr($r_bdy, $r_st, $r_end - $r_st);
				}
			}
		}
		if (strlen($r_evt_id) == 0) {
			$r_st = stripos($r_bdy, "name=\"_eventId\"", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name = \"_eventId\"", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name=\'_eventId\'", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name = \'_eventId\'", $r_nx);
			if ($r_st !== FALSE && $r_st < $r_end) {
				$r_p = stripos($r_bdy, "value=\"", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value = \"", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value=\'", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value = \'", $r_st);
				if ($r_p !== FALSE && $r_p < $r_end) {
					while ($r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
						$r_p++;
					$r_p++;
					$r_st = $r_p;
					while ($r_p < $r_end && $r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
						$r_p++;
					$r_end = $r_p;
					$r_evt_id = substr($r_bdy, $r_st, $r_end - $r_st);
				}
			}
		}
		if (strlen($r_sub) == 0) {
			$r_st = stripos($r_bdy, "name=\"submit\"", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name = \"submit\"", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name=\'submit\'", $r_nx);
			if ($r_st === FALSE || $r_st > $r_end)
				$r_st = stripos($r_bdy, "name = \'submit\'", $r_nx);
			if ($r_st !== FALSE && $r_st < $r_end) {
				$r_p = stripos($r_bdy, "value=\"", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value = \"", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value=\'", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = stripos($r_bdy, "value = \'", $r_st);
				if ($r_p !== FALSE && $r_p < $r_end) {
					while ($r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
						$r_p++;
					$r_p++;
					$r_st = $r_p;
					while ($r_p < $r_end && $r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
						$r_p++;
					$r_end = $r_p;
					$r_sub = substr($r_bdy, $r_st, $r_end - $r_st);
				}
			}
		}
		$r_p = $r_nx + 1;
	}
	if (strlen($r_ac) == 0 || strlen($r_lt) == 0) {
		curl_close($r_ch);
		return;
	}
	if (strlen($r_evt_id) == 0)
		unset($r_evt_id);
	if (isset($r_evt_id) && strlen($r_sub) == 0) {
		$r_sub = "LOGIN"; 
	}
	if (stripos($r_ac, "http://") !== 0
	  && stripos($r_ac, "https://") !== 0) {
		if ($r_ac[0] == "/") {
			$r_p = stripos($r_liu, "://");
			if ($r_p !== FALSE) {
				$r_p += 3;
				$r_p = stripos($r_liu, "/", $r_p);
				if ($r_p !== FALSE) {
					$r_acu = substr($r_liu, 0, $r_p);
					$r_acu .= $r_ac;
				}
			}
		} else {
			$r_p = stripos($r_liu, "/login?");
			if ($r_p !== FALSE) {
				$r_acu = substr($r_liu, 0, $r_p);
				$r_acu .= "/$r_ac";
			}
		}
	} else {
		$r_acu = $r_ac;
	}
	if (!isset($r_acu))
		$r_acu = $r_liu;
	$r_psf = "username=";
	$r_psf .= urlencode($r_usrn);
	$r_psf .= "&password=";
	$r_psf .= urlencode($r_pw);
	$r_psf .= "&lt=";
	$r_psf .= urlencode($r_lt);
	$r_psf .= "&service=";
	$r_psf .= urlencode($r_svu);
	if (isset($r_evt_id)) {
		$r_psf .= "&_eventId=";
		$r_psf .= urlencode($r_evt_id);
		$r_psf .= "&submit=";
		$r_psf .= urlencode($r_sub);
	}
	curl_setopt($r_ch, CURLOPT_URL, $r_acu);
	curl_setopt($r_ch, CURLOPT_HTTPGET, FALSE);
	curl_setopt($r_ch, CURLOPT_POST, TRUE);
	curl_setopt($r_ch, CURLOPT_POSTFIELDS, $r_psf);
	$r_rsp = curl_exec($r_ch);
	if ($r_rsp === FALSE) {
		curl_close($r_ch);
		return;
	}
	$r_p = 0;
	while (stripos($r_rsp, "HTTP/", $r_p) === 0) {
		$r_p = stripos($r_rsp, "\r\n\r\n", $r_p);
		if ($r_p === FALSE)
			break;
		$r_p += 4;
	}
	if ($r_p === 0) {
		$r_hdrs = "";
		$r_hset = "";
		$r_bdy = $r_rsp;
	} else if ($r_p === FALSE) {
		$r_hdrs = $r_rsp;
		$r_hset = explode("\r\n\r\n", $r_hdrs);
		$r_bdy = "";
	} else {
		$r_hdrs = substr($r_rsp, 0, $r_p - 4);
		$r_hset = explode("\r\n\r\n", $r_hdrs);
		$r_bdy = substr($r_rsp, $r_p);
	}
	foreach ($r_hset as $r_set) {
		$r_hdrl = explode("\r\n", $r_set);
		foreach ($r_hdrl as $r_hdr) {
			if (stripos($r_hdr, "Location:") !== FALSE) {
				$r_st = stripos($r_hdr, "?ticket=");
				if ($r_st === FALSE)
					$r_st = stripos($r_hdr, "&ticket=");
				if ($r_st !== FALSE) {
					$r_end = stripos($r_hdr, "&", $r_st + 1);
					if ($r_end === FALSE)
						$r_end = strlen($r_hdr);
					$r_pm = substr($r_hdr, $r_st + 8, $r_end - $r_st);
					if ($r_pm !== FALSE && strlen($r_pm) > 0) {
						$r_tkt = trim(urldecode($r_pm));
						break;
					}
				}
			}
		}
		if (isset($r_tkt))
			break;
	}
	$r_rurl = "";
	$r_p = 0;
	$r_l = strlen($r_bdy);
	while (strlen($r_rurl) == 0) {
		$r_nx = stripos($r_bdy, "window.location.href", $r_p);
		if ($r_nx === FALSE)
			$r_nx = stripos($r_bdy, "window.location.replace", $r_p);
		if ($r_nx === FALSE)
			$r_nx = stripos($r_bdy, "window.location", $r_p);
		if ($r_nx === FALSE)
			$r_nx = stripos($r_bdy, "window.navigate", $r_p);
		if ($r_nx === FALSE)
			$r_nx = stripos($r_bdy, "document.location.href", $r_p);
		if ($r_nx === FALSE)
			$r_nx = stripos($r_bdy, "document.location.URL", $r_p);
		if ($r_nx === FALSE)
			$r_nx = stripos($r_bdy, "document.location", $r_p);
		if ($r_nx === FALSE)
			break;
		$r_p = $r_nx;
		while ($r_p < $r_l && $r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
			$r_p++;
		if ($r_p < $r_l)
			$r_p++;
		$r_st = $r_p;
		while ($r_p < $r_end && $r_bdy[$r_p] != "\"" && $r_bdy[$r_p] != "\'")
			$r_p++;
		$r_end = $r_p;
		$r_rurl = substr($r_bdy, $r_st, $r_end - $r_st);
		$r_st = stripos($r_rurl, "?ticket=");
		if ($r_st === FALSE)
			$r_st = stripos($r_rurl, "&ticket=");
		if ($r_st !== FALSE) {
			$r_end = stripos($r_rurl, "&", $r_st + 1);
			if ($r_end === FALSE)
				$r_end = strlen($r_rurl);
			$r_pm = substr($r_rurl, $r_st + 8, $r_end - $r_st);
			if ($r_pm !== FALSE && strlen($r_pm) > 0)
				$r_tkt = trim(urldecode($r_pm));
		}
		if (!isset($r_tkt))
			$r_rurl = "";
		$r_p = $r_nx + 1;
	}
	if (strlen($r_rurl) != 0) {
		curl_setopt($r_ch, CURLOPT_URL, $r_rurl);
		curl_setopt($r_ch, CURLOPT_HTTPGET, TRUE);
		curl_setopt($r_ch, CURLOPT_POST, FALSE);
		curl_setopt($r_ch, CURLOPT_POSTFIELDS, "");
		$redir_res = curl_exec($r_ch);
		if ($redir_res !== FALSE) {
			$r_rsp = $redir_res;
			$r_p = 0;
			while (stripos($r_rsp, "HTTP/", $r_p) === 0) {
				$r_p = stripos($r_rsp, "\r\n\r\n", $r_p);
				if ($r_p === FALSE)
					break;
				$r_p += 4;
			}
			if ($r_p === 0) {
				$r_hdrs = "";
				$r_hset = "";
				$r_bdy = $r_rsp;
			} else if ($r_p === FALSE) {
				$r_hdrs = $r_rsp;
				$r_hset = explode("\r\n\r\n", $r_hdrs);
				$r_bdy = "";
			} else {
				$r_hdrs = substr($r_rsp, 0, $r_p - 4);
				$r_hset = explode("\r\n\r\n", $r_hdrs);
				$r_bdy = substr($r_rsp, $r_p);
			}
		}
	}
	$r_asu = "";
	$r_psf = "";
	if (strlen($r_rurl) == 0) {
	}
	if (strlen($r_asu) != 0) {
		curl_setopt($r_ch, CURLOPT_URL, $r_asu);
		curl_setopt($r_ch, CURLOPT_HTTPGET, FALSE);
		curl_setopt($r_ch, CURLOPT_POST, TRUE);
		curl_setopt($r_ch, CURLOPT_POSTFIELDS, $r_psf);
		$r_ares = curl_exec($r_ch);
		if ($r_ares !== FALSE) {
			$r_rsp = $r_ares;
			$r_p = 0;
			while (stripos($r_rsp, "HTTP/", $r_p) === 0) {
				$r_p = stripos($r_rsp, "\r\n\r\n", $r_p);
				if ($r_p === FALSE)
					break;
				$r_p += 4;
			}
			if ($r_p === 0) {
				$r_hdrs = "";
				$r_hset = "";
				$r_bdy = $r_rsp;
			} else if ($r_p === FALSE) {
				$r_hdrs = $r_rsp;
				$r_hset = explode("\r\n\r\n", $r_hdrs);
				$r_bdy = "";
			} else {
				$r_hdrs = substr($r_rsp, 0, $r_p - 4);
				$r_hset = explode("\r\n\r\n", $r_hdrs);
				$r_bdy = substr($r_rsp, $r_p);
			}
		}
	}
	if (!isset($r_tkt)) {
		$r_st = stripos($r_bdy, "<rwscas>");
		if ($r_st !== FALSE) {
			$r_end = stripos($r_bdy, "</rwscas>", $r_st);
			if ($r_end === FALSE)
				$r_end = strlen($r_hdr);
			$r_p = stripos($r_bdy, "<st>", $r_st);
			if ($r_p !== FALSE && $r_p < $r_end) {
				$r_p += 4;
				$r_st = $r_p;
				$r_p = stripos($r_bdy, "</st>", $r_st);
				if ($r_p === FALSE || $r_p > $r_end)
					$r_p = $r_end;
				$r_end = $r_p;
				$r_pm = trim(substr($r_bdy, $r_st, $r_end));
				if (strlen($r_pm))
					$r_tkt = $r_pm;
			}
		}
	}
	curl_close($r_ch);
	if (!isset($r_tkt))
		return;
	if (strlen($RWSSRURL) > 0)
		$r_rurl = $RWSSRURL;
	else
		$r_rurl = RWSGSUrl(FALSE, FALSE);
	$r_rurl .= "?rwscas=3"; 
	if (isset($r_bv)) {
		$r_rurl .= "&version=";
		$r_rurl .= urlencode($r_bv);
	}
	if (isset($r_usrn)) {
		$r_rurl .= "&rwsuser=";
		$r_rurl .= urlencode($r_usrn);
	}
	if (isset($r_pw)) {
		$r_rurl .= "&rwspass=";
		$r_rurl .= urlencode($r_pw);
	}
	if (isset($r_tkt)) {
		$r_rurl .= "&ticket=";
		$r_rurl .= urlencode($r_tkt);
	}
	header("Location: $r_rurl");
	exit;
}
function RWSPCReqs()
{
	global $RWSESL3;
	global $RWSCRURL;
	$r_rwc = RWSGSOpt("rwscas");
	if ($r_rwc === FALSE || strlen($r_rwc) == 0)
		return;
	if ($r_rwc != "1" && $r_rwc != "2" && $r_rwc != "3")
		return;
	$r_ver = RWSGSOpt("version");
	if ($r_ver === FALSE || strlen($r_ver) == 0)
		return;
	$r_rwu = RWSGSOpt("rwsuser");
	if ($r_rwu === FALSE || strlen($r_rwu) == 0)
		unset($r_rwu);
	$r_rwp = RWSGSOpt("rwspass");
	if ($r_rwp === FALSE || strlen($r_rwp) == 0)
		unset($r_rwp);
	$r_tkt = RWSGSOpt("ticket");
	if ($r_tkt === FALSE || strlen($r_tkt) == 0)
		unset($r_tkt);
	$r_pid = RWSGSOpt("pgtId");
	if ($r_pid === FALSE || strlen($r_pid) == 0)
		unset($r_pid);
	$r_piou = RWSGSOpt("pgtIou");
	if ($r_piou === FALSE || strlen($r_piou) == 0)
		unset($r_piou);
	$r_aus = get_enabled_auth_plugins();
	foreach ($r_aus as $r_aun) {
		$r_aup = get_auth_plugin($r_aun);
		if (strcasecmp($r_aup->authtype, RWSCAS) == 0) {
			$r_csp = $r_aup;
			break;
		}
	}
	if (!isset($r_csp))
		return;
	if (empty($r_csp->config->hostname))
		return;
	list($r_v1, $r_v2, $r_v3) = explode(".", phpCAS::getVersion());
	$r_csp->connectCAS();
	if ($r_rwc == "1") { 
		if (isset($r_tkt)) {
			RWSRHXml();
			echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
			echo "<rwscas>\r\n";
			echo "\t<st>";
			echo utf8_encode(htmlspecialchars(trim($r_tkt)));
			echo "\t</st>\r\n";
			echo "</rwscas>\r\n";
			exit;
		} else if ($_SERVER['REQUEST_METHOD'] == "GET") {
			$r_ok = phpCAS::checkAuthentication();
			if (!isset($r_rwu))
				$r_rwu = phpCAS::getUser();
			if (!isset($r_rwp))
				$r_rwp = "passwdCas"; 
			RWSAMUser($r_rwu, $r_rwp, $r_ok);
		} else if ($_SERVER['REQUEST_METHOD'] == "POST") {
			$r_psd = urldecode(file_get_contents("php://input"));
			if (stripos($r_psd, "<samlp:LogoutRequest ") !== FALSE)
				RWSAOLog();
		}
	} else if ($r_rwc == "2") { 
		if (isset($r_pid) && isset($r_piou)) {
			if ($r_csp->config->proxycas)
				phpCAS::checkAuthentication();
		} else if ($_SERVER['REQUEST_METHOD'] == "POST") {
			$r_psd = urldecode(file_get_contents("php://input"));
			if (stripos($r_psd, "<samlp:LogoutRequest ") !== FALSE)
				RWSAOLog();
		}
	} else if ($r_rwc == "3") { 
		if (isset($r_tkt)) {
			if (strlen($RWSCRURL) > 0)
				$r_svu = $RWSCRURL;
			else
				$r_svu = RWSGSUrl(FALSE, FALSE);
			$r_svu .= "?rwscas=1"; 
			if (isset($r_ver)) {
				$r_svu .= "&version=";
				$r_svu .= urlencode($r_ver);
			}
			if (isset($r_rwu)) {
				$r_svu .= "&rwsuser=";
				$r_svu .= urlencode($r_rwu);
			}
			if (isset($r_rwp)) {
				$r_svu .= "&rwspass=";
				$r_svu .= urlencode($r_rwp);
			}
			phpCAS::setFixedServiceURL($r_svu);
			if ($r_csp->config->proxycas) {
				if (strlen($RWSCRURL) > 0)
					$r_cbu = $RWSCRURL;
				else
					$r_cbu = RWSGSUrl(TRUE, FALSE);
				$r_cbu .= "?rwscas=2"; 
				if (isset($r_ver)) {
					$r_cbu .= "&version=";
					$r_cbu .= urlencode($r_ver);
				}
				if (isset($r_rwu)) {
					$r_cbu .= "&rwsuser=";
					$r_cbu .= urlencode($r_rwu);
				}
				if (isset($r_rwp)) {
					$r_cbu .= "&rwspass=";
					$r_cbu .= urlencode($r_rwp);
				}
					phpCAS::setFixedCallbackURL($r_cbu);
			}
			if (phpCAS::checkAuthentication())
				exit; 
			RWSAMUser($r_rwu, $r_rwp, TRUE);
		}
	}
	RWSSErr("2008"); 
}
function RWSCMMaint()
{
	global $CFG;
	if (is_siteadmin())
		return;
	if (!empty($CFG->maintenance_enabled)
	  || file_exists($CFG->dataroot . "/" . SITEID . "/maintenance.html")) {
		RWSSErr("2009");
	}
}
function RWSCMAuth()
{
	if (!isloggedin()) {
		RWSSErr("2010");
	}
}
function RWSCMUCourse($r_cid, $r_cqa=FALSE)
{
	global $DB;
	$r_rcd = $DB->get_record("course", array("id" => $r_cid));
	if ($r_rcd === FALSE) 
		RWSSErr("2011");
	if ($r_cqa && !course_allowed_module($r_rcd, "quiz")) {
		RWSSErr("2012");
	}
	if (!RWSIUMCourse($r_cid)) {
		RWSSErr("2013");
	}
	return $r_rcd; 
}
function RWSCMUQuiz($r_qzmi)
{
	global $DB;
	$r_rcd = $DB->get_record("course_modules", array("id" => $r_qzmi));
	if ($r_rcd === FALSE)
		RWSSErr("2014"); 
	if (!RWSIUMQuiz($r_qzmi)) {
		RWSSErr("2015");
	}
	return $r_rcd; 
}
function RWSGUQCats($r_cid)
{
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxs = array();
	if ($r_bv >= 2010063001) { 
		if (is_siteadmin()) {
			$r_sys = get_context_instance(CONTEXT_SYSTEM);
			$r_ctxs[] = $r_sys->id;
		}
	}
	$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_ctxs[] = $r_ctx->id;
	$r_qzms = RWSGUVQList($r_cid);
	if (count($r_qzms) > 0) {
		foreach ($r_qzms as $r_qzm) {
			$r_ctx = get_context_instance(CONTEXT_MODULE, $r_qzm->id);
			if ($r_ctx != FALSE) {
				if (!in_array($r_ctx->id, $r_ctxs))
					$r_ctxs[] = $r_ctx->id;
			}
		}
	}
	if (count($r_ctxs) == 0) {
		return array();
	}
	else if (count($r_ctxs) == 1) {
		$r_qcs = get_categories_for_contexts($r_ctxs[0]);
		if ($r_qcs === FALSE || count($r_qcs) == 0)
			return array();
	}
	else {
		$r_ctxl = implode(", ", $r_ctxs);
		$r_qcs = get_categories_for_contexts($r_ctxl);
		if ($r_qcs === FALSE || count($r_qcs) == 0)
			return array();
	}
	return $r_qcs;
}
function RWSGUVSList($r_cid)
{
	$r_vs = array();
	$r_secs = get_all_sections($r_cid);
	if ($r_secs === FALSE || count($r_secs) == 0)
		return $r_vs;
	$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_vh = has_capability("moodle/course:viewhiddensections", $r_ctx);
	if (!$r_vh) 
		$r_vh = is_siteadmin();
	foreach ($r_secs as $r_s) {
		if ($r_s->visible || $r_vh)
			$r_vs[] = $r_s;
	}
	return $r_secs;
}
function RWSGUVQList($r_cid)
{
	$r_vqms = array();
	$r_qzms = get_coursemodules_in_course("quiz", $r_cid);
	if ($r_qzms === FALSE || count($r_qzms) == 0)
		return $r_vqms;
	foreach ($r_qzms as $r_qzm) {
		if (coursemodule_visible_for_user($r_qzm))
			$r_vqms[] = $r_qzm;
    }
	return $r_vqms;
}
function RWSGUMQList($r_qzms)
{
	$r_mqms = array();
	if (!$r_qzms || count($r_qzms) == 0)
		return $r_mqms;
	foreach ($r_qzms as $r_qzm) {
		if (RWSIUMQuiz($r_qzm->id))
			$r_mqms[] = $r_qzm;
    }
	return $r_mqms;
}
function RWSIUMQuiz($r_qzmi)
{
	$r_ctx = get_context_instance(CONTEXT_MODULE, $r_qzmi);
	$r_ok = ($r_ctx !== FALSE);
	if ($r_ok)
		$r_ok = has_capability("mod/quiz:view", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("mod/quiz:preview", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("mod/quiz:manage", $r_ctx);
	if (!$r_ok)
		$r_ok = is_siteadmin();
	return $r_ok;
}
function RWSGUMCList()
{
	$r_mc = array();
	$r_crss = get_courses();
	if ($r_crss === FALSE || count($r_crss) == 0)
		return $r_mc;
    if (array_key_exists(SITEID, $r_crss))
        unset($r_crss[SITEID]);
	if (count($r_crss) == 0)
		return $r_mc;
	foreach ($r_crss as $r_c) {
		if (RWSIUMCourse($r_c->id))
			$r_mc[] = $r_c;
    }
	return $r_mc;
}
function RWSCMUSvc()
{
}
function RWSIUMCourse($r_cid)
{
	$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_ok = ($r_ctx !== FALSE);
	if ($r_ok)
		$r_ok = has_capability("moodle/site:viewfullnames", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:activityvisibility", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:viewhiddencourses", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:viewhiddenactivities", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:viewhiddensections", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:update", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:manageactivities", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/course:managefiles", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:managecategory", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:add", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:editmine", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:editall", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:viewmine", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:viewall", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:usemine", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:useall", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:movemine", $r_ctx);
	if ($r_ok)
		$r_ok = has_capability("moodle/question:moveall", $r_ctx);
	if (!$r_ok)
		$r_ok = is_siteadmin();
	return $r_ok;
}
function RWSGSOpt($r_nm)
{
	global $RWSECAS;
	if (isset($_POST[$r_nm])) {
		if (get_magic_quotes_gpc())
			return stripslashes($_POST[$r_nm]);
		else
			return $_POST[$r_nm];
	}
	if ($RWSECAS) {
		if (!isloggedin()) {
			if (isset($_GET[$r_nm])) {
				if (get_magic_quotes_gpc())
					return stripslashes($_GET[$r_nm]);
				else
					return $_GET[$r_nm];
			}
		}
	}
	if (isloggedin()) {
		if (isset($_FILES[$r_nm]))
		{
			if ($_FILES[$r_nm]['error'] == UPLOAD_ERR_OK )
			{
				$r_fl = new stdClass();
				$r_fl->filename = $_FILES[$r_nm]['name'];
				$r_fl->filedata = file_get_contents($_FILES[$r_nm]['tmp_name']);
				return $r_fl;
			}
		}
	}
	return FALSE;
}
function RWSSQDLocal(&$r_qiz)
{
	global $DB;
	global $CFG;
	if (!empty($r_qiz->coursemodule)) {
		$r_ctx = get_context_instance(CONTEXT_MODULE, $r_qiz->coursemodule);
		$r_ctxi = $r_ctx->id;
	} else if (!empty($r_qiz->course)) {
		$r_ctx = get_context_instance(CONTEXT_COURSE, $r_qiz->course);
		$r_ctxi = $r_ctx->id;
	} else {
		$r_ctxi = null;
	}
	$r_qiz->intro = "";
	$r_qiz->introformat = FORMAT_HTML;
	$r_qiz->timeopen = 0; 
	$r_qiz->timeclose = 0; 
	$r_qiz->timelimitenable = 0; 
	$r_qiz->timelimit = 0; 
	$r_qiz->attempts = 0; 
	$r_qiz->grademethod = 1; 
	$r_qiz->questionsperpage = 0; 
	$r_qiz->shufflequestions = 0; 
	$r_qiz->shuffleanswers = 1; 
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->preferredbehaviour = "adaptive";
	}
	else { 
		$r_qiz->adaptive = 1; 
		$r_qiz->penaltyscheme = 1; 
	}
	$r_qiz->attemptonlast = 0; 
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptduring = 1;				
		$r_qiz->correctnessduring = 1;			
		$r_qiz->marksduring = 1;					
		$r_qiz->specificfeedbackduring = 1;		
		$r_qiz->generalfeedbackduring = 1;		
		$r_qiz->rightanswerduring = 1;			
		$r_qiz->overallfeedbackduring = 1;		
	}
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptimmediately = 1;			
		$r_qiz->correctnessimmediately = 1;		
		$r_qiz->marksimmediately = 1;			
		$r_qiz->specificfeedbackimmediately = 1;	
		$r_qiz->generalfeedbackimmediately = 1;	
		$r_qiz->rightanswerimmediately = 1;		
		$r_qiz->overallfeedbackimmediately = 1;	
	}
	else { 
		$r_qiz->responsesimmediately = 1;		
		$r_qiz->answersimmediately = 1;			
		$r_qiz->feedbackimmediately = 1;			
		$r_qiz->generalfeedbackimmediately = 1;	
		$r_qiz->scoreimmediately = 1;			
		$r_qiz->overallfeedbackimmediately = 1;	
	}
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptopen = 1;				
		$r_qiz->correctnessopen = 1;			
		$r_qiz->marksopen = 1;				
		$r_qiz->specificfeedbackopen = 1;	
		$r_qiz->generalfeedbackopen = 1;		
		$r_qiz->rightansweropen = 1;			
		$r_qiz->overallfeedbackopen = 1;		
	}
	else { 
		$r_qiz->responsesopen = 1;		
		$r_qiz->answersopen = 1;			
		$r_qiz->feedbackopen = 1;		
		$r_qiz->generalfeedbackopen = 1;	
		$r_qiz->scoreopen = 1;			
		$r_qiz->overallfeedbackopen = 1;	
	}
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptclosed = 1;			
		$r_qiz->correctnessclosed = 1;		
		$r_qiz->marksclosed = 1;				
		$r_qiz->specificfeedbackclosed = 1;	
		$r_qiz->generalfeedbackclosed = 1;	
		$r_qiz->rightanswerclosed = 1;		
		$r_qiz->overallfeedbackclosed = 1;	
	}
	else { 
		$r_qiz->responsesclosed = 1;			
		$r_qiz->answersclosed = 1;			
		$r_qiz->feedbackclosed = 1;			
		$r_qiz->generalfeedbackclosed = 1;	
		$r_qiz->scoreclosed = 1;				
		$r_qiz->overallfeedbackclosed = 1;	
	}
	$r_qiz->showuserpicture = 0; 
	$r_qiz->decimalpoints = 2; 
	$r_qiz->questiondecimalpoints = -1; 
	$r_qiz->showblocks = 0; 
	$r_qiz->quizpassword = ""; 
	$r_qiz->subnet = ""; 
	$r_qiz->delay1 = 0; 
	$r_qiz->delay2 = 0; 
	$r_qiz->popup = 0; 
	$r_nf = 5; 
	for ($r_i = 0; $r_i < $r_nf; $r_i++) {
		$r_drf = 0;
		$r_cmp = "mod_quiz";
		$r_far = "feedback";
		$r_iti = null;
		$r_op = null;
		$r_txt = ""; 
		$r_qiz->feedbacktext[$r_i]["text"] = file_prepare_draft_area(
		  $r_drf, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_op, $r_txt
		  );
		$r_qiz->feedbacktext[$r_i]["format"] = FORMAT_HTML;
		$r_qiz->feedbacktext[$r_i]["itemid"] = $r_drf;
		if ($r_i < $r_nf - 1)
			$r_qiz->feedbackboundaries[$r_i] = ""; 
	}
	$r_qiz->groupmode = NOGROUPS; 
	$r_qiz->groupingid = 0; 
	$r_qiz->visible = 1; 
	$r_qiz->cmidnumber = ""; 
	if (!empty($r_qiz->course)) {
		$r_crs = $DB->get_record("course", array("id" => $r_qiz->course));
		if ($r_crs !== FALSE && $r_crs->groupmodeforce) {
			$r_qiz->groupmode = $r_crs->groupmode;
			$r_qiz->groupingid = $r_crs->defaultgroupingid;
		}
	}
	$r_qiz->grade = 10; 
}
function RWSSQDMoodle(&$r_qiz)
{
	global $DB;
	global $CFG;
	if (!empty($r_qiz->coursemodule)) {
		$r_ctx = get_context_instance(CONTEXT_MODULE, $r_qiz->coursemodule);
		$r_ctxi = $r_ctx->id;
	} else if (!empty($r_qiz->course)) {
		$r_ctx = get_context_instance(CONTEXT_COURSE, $r_qiz->course);
		$r_ctxi = $r_ctx->id;
	} else {
		$r_ctxi = null;
	}
	$r_dfs = get_config("quiz");
	$r_qiz->intro = ""; 
	$r_qiz->introformat = FORMAT_HTML;
	$r_qiz->timeopen = 0;  
	$r_qiz->timeclose = 0; 
	if ($r_dfs->timelimit > 0)
		$r_qiz->timelimitenable = 1;
	else
		$r_qiz->timelimitenable = 0;
	$r_qiz->timelimit = $r_dfs->timelimit;
	$r_qiz->attempts = $r_dfs->attempts;
	$r_qiz->grademethod = $r_dfs->grademethod;
	$r_qiz->questionsperpage = $r_dfs->questionsperpage;
	$r_qiz->shufflequestions = $r_dfs->shufflequestions;
	$r_qiz->shuffleanswers = $r_dfs->shuffleanswers;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->preferredbehaviour = $r_dfs->preferredbehaviour;
	}
	else { 
		$r_qiz->adaptive = $r_dfs->optionflags & RWSQAD;
		$r_qiz->penaltyscheme = $r_dfs->penaltyscheme;
	}
	$r_qiz->attemptonlast = $r_dfs->attemptonlast;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptduring = $r_dfs->reviewattempt & RWSRDU;
		if (!$r_qiz->attemptduring)
			unset($r_qiz->attemptduring);
		$r_qiz->correctnessduring = $r_dfs->reviewcorrectness & RWSRDU;
		if (!$r_qiz->correctnessduring)
			unset($r_qiz->correctnessduring);
		$r_qiz->marksduring = $r_dfs->reviewmarks & RWSRDU;
		if (!$r_qiz->marksduring)
			unset($r_qiz->marksduring);
		$r_qiz->specificfeedbackduring = $r_dfs->reviewspecificfeedback & RWSRDU;
		if (!$r_qiz->specificfeedbackduring)
			unset($r_qiz->specificfeedbackduring);
		$r_qiz->generalfeedbackduring = $r_dfs->reviewgeneralfeedback & RWSRDU;
		if (!$r_qiz->generalfeedbackduring)
			unset($r_qiz->generalfeedbackduring);
		$r_qiz->rightanswerduring = $r_dfs->reviewrightanswer & RWSRDU;
		if (!$r_qiz->rightanswerduring)
			unset($r_qiz->rightanswerduring);
		$r_qiz->overallfeedbackduring = $r_dfs->reviewoverallfeedback & RWSRDU;
		if (!$r_qiz->overallfeedbackduring)
			unset($r_qiz->overallfeedbackduring);
	}
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptimmediately = $r_dfs->reviewattempt & RWSRIA;
		if (!$r_qiz->attemptimmediately)
			unset($r_qiz->attemptimmediately);
		$r_qiz->correctnessimmediately = $r_dfs->reviewcorrectness & RWSRIA;
		if (!$r_qiz->correctnessimmediately)
			unset($r_qiz->correctnessimmediately);
		$r_qiz->marksimmediately = $r_dfs->reviewmarks & RWSRIA;
		if (!$r_qiz->marksimmediately)
			unset($r_qiz->marksimmediately);
		$r_qiz->specificfeedbackimmediately = $r_dfs->reviewspecificfeedback & RWSRIA;
		if (!$r_qiz->specificfeedbackimmediately)
			unset($r_qiz->specificfeedbackimmediately);
		$r_qiz->generalfeedbackimmediately = $r_dfs->reviewgeneralfeedback & RWSRIA;
		if (!$r_qiz->generalfeedbackimmediately)
			unset($r_qiz->generalfeedbackimmediately);
		$r_qiz->rightanswerimmediately = $r_dfs->reviewrightanswer & RWSRIA;
		if (!$r_qiz->rightanswerimmediately)
			unset($r_qiz->rightanswerimmediately);
		$r_qiz->overallfeedbackimmediately = $r_dfs->reviewoverallfeedback & RWSRIA;
		if (!$r_qiz->overallfeedbackimmediately)
			unset($r_qiz->overallfeedbackimmediately);
	}
	else { 
		$r_qiz->responsesimmediately = $r_dfs->review & RWSRRE & RWSRIM;
		if (!$r_qiz->responsesimmediately)
			unset($r_qiz->responsesimmediately);
		$r_qiz->answersimmediately = $r_dfs->review & RWSRAN & RWSRIM;
		if (!$r_qiz->answersimmediately)
			unset($r_qiz->answersimmediately);
		$r_qiz->feedbackimmediately = $r_dfs->review & RWSRFE & RWSRIM;
		if (!$r_qiz->feedbackimmediately)
			unset($r_qiz->feedbackimmediately);
		$r_qiz->generalfeedbackimmediately = $r_dfs->review & RWSRGE & RWSRIM;
		if (!$r_qiz->generalfeedbackimmediately)
			unset($r_qiz->generalfeedbackimmediately);
		$r_qiz->scoreimmediately = $r_dfs->review & RWSRSC & RWSRIM;
		if (!$r_qiz->scoreimmediately)
			unset($r_qiz->scoreimmediately);
		$r_qiz->overallfeedbackimmediately = $r_dfs->review & RWSROV & RWSRIM;
		if (!$r_qiz->overallfeedbackimmediately)
			unset($r_qiz->overallfeedbackimmediately);
	}
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptopen = $r_dfs->reviewattempt & RWSRLA;
		if (!$r_qiz->attemptopen)
			unset($r_qiz->attemptopen);
		$r_qiz->correctnessopen = $r_dfs->reviewcorrectness & RWSRLA;
		if (!$r_qiz->correctnessopen)
			unset($r_qiz->correctnessopen);
		$r_qiz->marksopen = $r_dfs->reviewmarks & RWSRLA;
		if (!$r_qiz->marksopen)
			unset($r_qiz->marksopen);
		$r_qiz->specificfeedbackopen = $r_dfs->reviewspecificfeedback & RWSRLA;
		if (!$r_qiz->specificfeedbackopen)
			unset($r_qiz->specificfeedbackopen);
		$r_qiz->generalfeedbackopen = $r_dfs->reviewgeneralfeedback & RWSRLA;
		if (!$r_qiz->generalfeedbackopen)
			unset($r_qiz->generalfeedbackopen);
		$r_qiz->rightansweropen = $r_dfs->reviewrightanswer & RWSRLA;
		if (!$r_qiz->rightansweropen)
			unset($r_qiz->rightansweropen);
		$r_qiz->overallfeedbackopen = $r_dfs->reviewoverallfeedback & RWSRLA;
		if (!$r_qiz->overallfeedbackopen)
			unset($r_qiz->overallfeedbackopen);
	}
	else { 
		$r_qiz->responsesopen = $r_dfs->review & RWSRRE & RWSROP;
		if (!$r_qiz->responsesopen)
			unset($r_qiz->responsesopen);
		$r_qiz->answersopen = $r_dfs->review & RWSRAN & RWSROP;
		if (!$r_qiz->answersopen)
			unset($r_qiz->answersopen);
		$r_qiz->feedbackopen = $r_dfs->review & RWSRFE & RWSROP;
		if (!$r_qiz->feedbackopen)
			unset($r_qiz->feedbackopen);
		$r_qiz->generalfeedbackopen = $r_dfs->review & RWSRGE & RWSROP;
		if (!$r_qiz->generalfeedbackopen)
			unset($r_qiz->generalfeedbackopen);
		$r_qiz->scoreopen = $r_dfs->review & RWSRSC & RWSROP;
		if (!$r_qiz->scoreopen)
			unset($r_qiz->scoreopen);
		$r_qiz->overallfeedbackopen = $r_dfs->review & RWSROV & RWSROP;
		if (!$r_qiz->overallfeedbackopen)
			unset($r_qiz->overallfeedbackopen);
	}
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptclosed = $r_dfs->reviewattempt & RWSRAF;
		if (!$r_qiz->attemptclosed)
			unset($r_qiz->attemptclosed);
		$r_qiz->correctnessclosed = $r_dfs->reviewcorrectness & RWSRAF;
		if (!$r_qiz->correctnessclosed)
			unset($r_qiz->correctnessclosed);
		$r_qiz->marksclosed = $r_dfs->reviewmarks & RWSRAF;
		if (!$r_qiz->marksclosed)
			unset($r_qiz->marksclosed);
		$r_qiz->specificfeedbackclosed = $r_dfs->reviewspecificfeedback & RWSRAF;
		if (!$r_qiz->specificfeedbackclosed)
			unset($r_qiz->specificfeedbackclosed);
		$r_qiz->generalfeedbackclosed = $r_dfs->reviewgeneralfeedback & RWSRAF;
		if (!$r_qiz->generalfeedbackclosed)
			unset($r_qiz->generalfeedbackclosed);
		$r_qiz->rightanswerclosed = $r_dfs->reviewrightanswer & RWSRAF;
		if (!$r_qiz->rightanswerclosed)
			unset($r_qiz->rightanswerclosed);
		$r_qiz->overallfeedbackclosed = $r_dfs->reviewoverallfeedback & RWSRAF;
		if (!$r_qiz->overallfeedbackclosed)
			unset($r_qiz->overallfeedbackclosed);
	}
	else { 
		$r_qiz->responsesclosed = $r_dfs->review & RWSRRE & RWSRCL;
		if (!$r_qiz->responsesclosed)
			unset($r_qiz->responsesclosed);
		$r_qiz->answersclosed = $r_dfs->review & RWSRAN & RWSRCL;
		if (!$r_qiz->answersclosed)
			unset($r_qiz->answersclosed);
		$r_qiz->feedbackclosed = $r_dfs->review & RWSRFE & RWSRCL;
		if (!$r_qiz->feedbackclosed)
			unset($r_qiz->feedbackclosed);
		$r_qiz->generalfeedbackclosed = $r_dfs->review & RWSRGE & RWSRCL;
		if (!$r_qiz->generalfeedbackclosed)
			unset($r_qiz->generalfeedbackclosed);
		$r_qiz->scoreclosed = $r_dfs->review & RWSRSC & RWSRCL;
		if (!$r_qiz->scoreclosed)
			unset($r_qiz->scoreclosed);
		$r_qiz->overallfeedbackclosed = $r_dfs->review & RWSROV & RWSRCL;
		if (!$r_qiz->overallfeedbackclosed)
			unset($r_qiz->overallfeedbackclosed);
	}
	$r_qiz->showuserpicture = $r_dfs->showuserpicture;
	$r_qiz->decimalpoints = $r_dfs->decimalpoints;
	$r_qiz->questiondecimalpoints = $r_dfs->questiondecimalpoints;
	$r_qiz->showblocks = $r_dfs->showblocks;
	$r_qiz->quizpassword = $r_dfs->password;
	$r_qiz->subnet = $r_dfs->subnet;
	$r_qiz->delay1 = $r_dfs->delay1;
	$r_qiz->delay2 = $r_dfs->delay2;
	$r_qiz->popup = $r_dfs->popup;
	$r_nf = 5; 
	for ($r_i = 0; $r_i < $r_nf; $r_i++) {
		$r_drf = 0;
		$r_cmp = "mod_quiz";
		$r_far = "feedback";
		$r_iti = null;
		$r_op = null;
		$r_txt = ""; 
		$r_qiz->feedbacktext[$r_i]["text"] = file_prepare_draft_area(
		  $r_drf, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_op, $r_txt
		  );
		$r_qiz->feedbacktext[$r_i]["format"] = FORMAT_HTML;
		$r_qiz->feedbacktext[$r_i]["itemid"] = $r_drf;
		if ($r_i < $r_nf - 1)
			$r_qiz->feedbackboundaries[$r_i] = ""; 
	}
	$r_qiz->groupmode = NOGROUPS;
	$r_qiz->groupingid = 0;
	$r_qiz->visible = 1;
	$r_qiz->cmidnumber = ""; 
	if (!empty($r_qiz->course)) {
		$r_crs = $DB->get_record("course", array("id" => $r_qiz->course));
		if ($r_crs !== FALSE) {
			$r_qiz->groupmode = $r_crs->groupmode;
			$r_qiz->groupingid = $r_crs->defaultgroupingid;
			if (!empty($r_qiz->section)) {
				$r_sec = get_course_section($r_qiz->section, $r_qiz->course);
				$r_qiz->visible = $r_sec->visible;
			}
		}
	}
	$r_qiz->grade = $r_dfs->maximumgrade;
}
function RWSSQDefs(&$r_qiz, $r_pop=FALSE)
{
	global $RWSLB;
		RWSSQDMoodle($r_qiz);
	$RWSLB->atts = 0; 
	$RWSLB->revs = 0; 
	$RWSLB->pw = ""; 
	if ($r_pop) {
		if (is_null($r_qiz->quizpassword) && !is_null($r_qiz->password))
			$r_qiz->quizpassword = $r_qiz->password;
		quiz_process_options($r_qiz);
	}
}
function RWSIQSet(
  &$r_qiz, $r_sfl, $r_sd, $r_ecd, $r_pop=FALSE)
{
	$r_clnid = FALSE;
	$r_clnif = FALSE;
	$r_cloif = FALSE;
	if ($r_ecd) {
		$r_dcd = base64_decode($r_sd);
		if ($r_dcd === FALSE) {
			RWSSErr("2017");
		}
	}
	else { 
		$r_dcd = $r_sd;
	}
	$r_imd = RWSMTFldr();
	$r_ok = ($r_imd !== FALSE);
	$r_clnid = $r_ok;
	if (!$r_ok) 
		$r_err = "2018";
	if ($r_ok) {
		$r_ok = RWSDIData($r_dcd, $r_imd);
		if (!$r_ok) 
			$r_err = "2019";
	}
	if ($r_ok) {
		$r_p = strrpos($r_sfl, ".");
		$r_ok = ($r_p !== FALSE && $r_p !== 0);
		if (!$r_ok) 
			$r_err = "2020"; 
	}
	if ($r_ok) {
		$r_imf = "$r_imd/";
		if ($r_p === FALSE) 
			$r_imf .= $r_sfl;
		else 
			$r_imf .= substr($r_sfl, 0, $r_p);
		$r_imf .= ".dat";
		$r_ok = file_exists($r_imf);
		$r_clnif = $r_ok;
		if (!$r_ok)
			$r_err = "2020"; 
	}
	if ($r_ok) {
		$r_hdl = fopen($r_imf, "rb");
		$r_ok = ($r_hdl !== FALSE);
		$r_cloif = $r_ok;
		if (!$r_ok)
			$r_err = "2021"; 
	}
	if ($r_ok) {
		$r_ok = RWSCSFSig($r_hdl);
		if (!$r_ok)
			$r_err = "2022"; 
	}
	if ($r_ok) {
		$r_ok = RWSCSFVer($r_hdl);
		if (!$r_ok)
			$r_err = "2023"; 
	}	
	if ($r_ok) {
		$r_rcd = RWSRSRec($r_hdl);
		$r_ok = ($r_rcd !== FALSE);
		if (!$r_ok)
			$r_err = "2024"; 
	}
	if ($r_ok) {
		$r_ok = RWSISRec($r_qiz, $r_rcd, $r_pop);
		if (!$r_ok)
			$r_err = "2025"; 
	}
	if ($r_cloif)
		fclose($r_hdl);
	if ($r_clnif && file_exists($r_imf))
		unlink($r_imf);
	if ($r_clnid && file_exists($r_imd))
		rmdir($r_imd);
	if (!$r_ok)
		RWSSErr($r_err);
}
function RWSEQSet($r_qiz, &$r_sfl, $r_w64)
{
		$r_fv = 0; 
	$r_fnc = "rwsexportsdata.zip";
	$r_fnu = "rwsexportsdata.dat";
	$r_sfl = "";
	$r_clned = FALSE;
	$r_clnef = FALSE;
	$r_clncf = FALSE;
	$r_cloef = FALSE;
	$r_ok = TRUE;
	if ($r_ok) {
		$r_exd = RWSMTFldr();
		$r_ok = ($r_exd !== FALSE);
		$r_clned = $r_ok;
		if (!$r_ok) 
			$r_err = "2026";
	}
	if ($r_ok) {
		$r_exf = "$r_exd/$r_fnu";
		$r_hdl = fopen($r_exf, "wb"); 
		$r_ok = ($r_hdl !== FALSE);
		$r_clnef = $r_ok;
		$r_cloef = $r_ok;
		if (!$r_ok)
			$r_err = "2027"; 
	}
	if ($r_ok) {
			$r_dat = pack("C*", 0x21, 0xfd, 0x65, 0x0d, 0x6e, 0xae, 0x4d, 0x01,
			  0x86, 0x78, 0xf5, 0x13, 0x00, 0x86, 0x99, 0x2a);
		$r_dat .= pack("n", $r_fv);
		$r_by = fwrite($r_hdl, $r_dat);
		$r_ok = ($r_by !== FALSE);
		if (!$r_ok)
			$r_err = "2028"; 
	}
	if ($r_ok) {
		$r_rcd = RWSESRec($r_qiz);
		$r_ok = ($r_rcd !== FALSE);
		if (!$r_ok)
			$r_err = "2029"; 
    }
	if ($r_ok) {
		$r_ok = RWSWSRec($r_hdl, $r_rcd);
		if (!$r_ok)
			$r_err = "2028"; 
	}
	if ($r_cloef)
		fclose($r_hdl);
	if ($r_ok) {
		$r_cf = "$r_exd/$r_fnc";
		$r_ok = RWSCEData($r_exf, $r_cf);
		$r_clncf = $r_ok;
		if (!$r_ok)
			$r_err = "2031"; 
	}
	if ($r_ok) {
		$r_cpr = file_get_contents($r_cf);
		$r_ok = ($r_cpr !== FALSE);
		if (!$r_ok)
			$r_err = "2032"; 
	}
	if ($r_ok && $r_w64)
		$r_ecd = base64_encode($r_cpr);
	if ($r_clnef && file_exists($r_exf))
		unlink($r_exf);
	if ($r_clncf && file_exists($r_cf))
		unlink($r_cf);
	if ($r_clned && file_exists($r_exd))
		rmdir($r_exd);
	if (!$r_ok)
		RWSSErr($r_err);
	$r_sfl = $r_fnc;
	if ($r_w64)
		return $r_ecd;
	else
		return $r_cpr;
}
function RWSIQues(
  $r_cid, $r_qci, $r_qfl, $r_qd, $r_ecd, &$r_drp, &$r_ba)
{
	$r_impd = 0;
	$r_drp = 0;
	$r_ba = 0;
	$r_br = 0;
	$r_clnid = FALSE;
	$r_clnif = FALSE;
	$r_cloif = FALSE;
	if ($r_ecd) {
		$r_dcd = base64_decode($r_qd);
		if ($r_dcd === FALSE) {
			RWSSErr("2033");
		}
	}
	else { 
		$r_dcd = $r_qd;
	}
	$r_imd = RWSMTFldr();
	$r_ok = ($r_imd !== FALSE);
	$r_clnid = $r_ok;
	if (!$r_ok)
		$r_err = "2034"; 
	if ($r_ok) {
		$r_ok = RWSDIData($r_dcd, $r_imd);
		if (!$r_ok)
			$r_err = "2035"; 
	}
	if ($r_ok) {
		$r_p = strrpos($r_qfl, ".");
		$r_ok = ($r_p !== FALSE && $r_p !== 0);
		if (!$r_ok) 
			$r_err = "2036"; 
	}
	if ($r_ok) {
		$r_imf = "$r_imd/";
		if ($r_p === FALSE) 
			$r_imf .= $r_qfl;
		else 
			$r_imf .= substr($r_qfl, 0, $r_p);
		$r_imf .= ".dat";
		$r_ok = file_exists($r_imf);
		$r_clnif = $r_ok;
		if (!$r_ok)
			$r_err = "2036"; 
	}
	if ($r_ok) {
		$r_hdl = fopen($r_imf, "rb");
		$r_ok = ($r_hdl !== FALSE);
		$r_cloif = $r_ok;
		if (!$r_ok)
			$r_err = "2037"; 
	}
	if ($r_ok) {
		$r_ok = RWSCQFSig($r_hdl);
		if (!$r_ok)
			$r_err = "2038"; 
	}
	if ($r_ok) {
		$r_ok = RWSCQFVer($r_hdl);
		if (!$r_ok)
			$r_err = "2039"; 
	}	
	if ($r_ok) {
		$r_qsti = array();
		$r_rcd = RWSRNQRec($r_hdl);
		while ($r_rcd !== FALSE) {
			$r_typ = RWSGQRType($r_rcd);
			switch ($r_typ) {
			case RWSATT:
				$r_sbp = RWSIARec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSSHA:
				$r_qi = RWSISARec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSTRF:
				$r_qi = RWSITFRec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSMCH:
				$r_qi = RWSIMCRec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSMAT:
				$r_qi = RWSIMRec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSDES:
				$r_qi = RWSIDRec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSESS:
				$r_qi = RWSIERec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSCAL:
				$r_qi = RWSICRec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSMAN: 
				$r_qi = RWSIMARec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSRSV:
				$r_res = RWSIRRec($r_cid, $r_qci, $r_rcd);
				break;
			case RWSCSI:
			case RWSCMU:
			case RWSRND:
			case RWSNUM:
			case RWSRSM:
			case RWSUNK:
			default:
				$r_qi = FALSE;
				break;
			}
			if ($r_typ == RWSATT) {
				if ($r_sbp === FALSE)
					$r_ba++;
			}
			else if ($r_typ == RWSRSV) {
				if ($r_res === FALSE)
					$r_br++;
			}
			else { 
				if ($r_qi === FALSE)
					$r_drp++;
				else {
					$r_impd++;
					$r_qsti[] = $r_qi;
				}
			}
			$r_rcd = RWSRNQRec($r_hdl);
		}
	}
	if ($r_cloif)
		fclose($r_hdl);
	if ($r_clnif && file_exists($r_imf))
		unlink($r_imf);
	if ($r_clnid && file_exists($r_imd))
		rmdir($r_imd);
	if (!$r_ok)
		RWSSErr($r_err);
	if ($r_impd == 0) {
		if ($r_drp == 0) 
			RWSSErr("2040");
		else 
			RWSSErr("2041");
	}
	return $r_qsti;
}
function RWSCQFSig($r_hdl)
{
	$r_es =	array(0xe1, 0x8a, 0x3b, 0xaf, 0xd0, 0x30, 0x4d, 0xce,
	  0xb4, 0x75, 0x8a, 0xdf, 0x1e, 0xa9, 0x08, 0x36);
	if (feof($r_hdl))
		return FALSE;
	$r_bf = fread($r_hdl, 16);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_as = array_values(unpack("C*", $r_bf));
	$r_ct = count($r_es);
	if ($r_ct != count($r_as))
		return FALSE;
	for($r_i = 0; $r_i < $r_ct; $r_i++) {
		if ($r_as[$r_i] != $r_es[$r_i])
			return FALSE;		
	}
	return TRUE;
}
function RWSCSFSig($r_hdl)
{
	$r_es =	array(0x07, 0x0b, 0x28, 0x3a, 0x98, 0xfa, 0x4c, 0xcd,
	  0x8a, 0x62, 0x14, 0xa7, 0x97, 0x33, 0x84, 0x37);
	if (feof($r_hdl))
		return FALSE;
	$r_bf = fread($r_hdl, 16);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_as = array_values(unpack("C*", $r_bf));
	$r_ct = count($r_es);
	if ($r_ct != count($r_as))
		return FALSE;
	for($r_i = 0; $r_i < $r_ct; $r_i++) {
		if ($r_as[$r_i] != $r_es[$r_i])
			return FALSE;		
	}
	return TRUE;
}
function RWSCQFVer($r_hdl)
{
	$r_ev = 0; 
	if (feof($r_hdl))
		return FALSE;
	$r_bf = fread($r_hdl, 2);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_dat = unpack("n", $r_bf);
	$r_av = $r_dat[1];
	if ($r_av == $r_ev)
		return TRUE;
	else
		return FALSE;
}
function RWSCSFVer($r_hdl)
{
	$r_ev = 0; 
	if (feof($r_hdl))
		return FALSE;
	$r_bf = fread($r_hdl, 2);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_dat = unpack("n", $r_bf);
	$r_av = $r_dat[1];
	if ($r_av == $r_ev)
		return TRUE;
	else
		return FALSE;
}
function RWSRSRec($r_hdl)
{
	if (feof($r_hdl))
		return FALSE;
	$r_cpos = ftell($r_hdl);
	if(fseek($r_hdl, 0, SEEK_END) != 0)
		return FALSE;
	$r_ep = ftell($r_hdl);
	$r_sz = $r_ep - $r_cpos;
	if(fseek($r_hdl, $r_cpos, SEEK_SET) != 0)
		return FALSE;
	$r_rcd = fread($r_hdl, $r_sz);
	if ($r_rcd === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	for ($r_i = 0; $r_i < $r_sz; $r_i++) {
		$r_dat = unpack("C", $r_rcd[$r_i]);
		$r_n = (intval($r_dat[1]) ^ 0x55) - 1;
		if ($r_n < 0)
			$r_n = 255;
		$r_rcd[$r_i] = pack("C", $r_n);
	}
	return $r_rcd;
}
function RWSWSRec($r_hdl, $r_rcd)
{
	$r_ok = TRUE;
	$r_l = strlen($r_rcd);
	for ($r_i = 0; $r_i < $r_l; $r_i++) {
		$r_dat = unpack("C", $r_rcd[$r_i]);
			$r_n = intval($r_dat[1]) - 1;
			if ($r_n < 0)
				$r_n = 255;
			$r_n ^= 0xaa;
		$r_rcd[$r_i] = pack("C", $r_n);
	}
	if ($r_l > 0) {
		$r_by = fwrite($r_hdl, $r_rcd);
		$r_ok = ($r_by !== FALSE);
	}
	return $r_ok;
}
function RWSRNQRec($r_hdl)
{
	$r_rcd = "";
	if (feof($r_hdl))
		return FALSE;
	$r_bf = fread($r_hdl, 1);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_rcd .= $r_bf;
	$r_bf = fread($r_hdl, 4);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_rcd .= $r_bf;
	$r_sz = strlen($r_bf);
	for ($r_i = 0; $r_i < $r_sz; $r_i++) {
		$r_dat = unpack("C", $r_bf[$r_i]);
		$r_n = (intval($r_dat[1]) ^ 0x55) - 1;
		if ($r_n < 0)
			$r_n = 255;
		$r_bf[$r_i] = pack("C", $r_n);
	}
	$r_dat = unpack("N", $r_bf);
	$r_sz = $r_dat[1];
	if ($r_sz < 1)
		return FALSE;
	$r_bf = fread($r_hdl, $r_sz);
	if ($r_bf === FALSE)
		return FALSE;
	if (feof($r_hdl))
		return FALSE;
	$r_rcd .= $r_bf;
	$r_sz = strlen($r_rcd); 
	for ($r_i = 0; $r_i < $r_sz; $r_i++) {
		$r_dat = unpack("C", $r_rcd[$r_i]);
		$r_n = (intval($r_dat[1]) ^ 0x55) - 1;
		if ($r_n < 0)
			$r_n = 255;
		$r_rcd[$r_i] = pack("C", $r_n);
	}
	return $r_rcd;
}
function RWSWNQRec($r_hdl, $r_rcd)
{
	$r_ok = TRUE;
	$r_l = strlen($r_rcd);
	for ($r_i = 0; $r_i < $r_l; $r_i++) {
		$r_dat = unpack("C", $r_rcd[$r_i]);
			$r_n = intval($r_dat[1]) - 1;
			if ($r_n < 0)
				$r_n = 255;
			$r_n ^= 0xaa;
		$r_rcd[$r_i] = pack("C", $r_n);
	}
	if ($r_l > 0) {
		$r_by = fwrite($r_hdl, $r_rcd);
		$r_ok = ($r_by !== FALSE);
	}
	return $r_ok;
}
function RWSGQRType($r_rcd)
{
	$r_dat = unpack("C", $r_rcd[0]);
	$r_typ = intval($r_dat[1]);
	switch ($r_typ) {
	case 0:
		return RWSATT;
	case 1:
		return RWSMCH;
	case 2:
		return RWSTRF;
	case 3:
		return RWSSHA;
	case 4:
		return RWSESS;
	case 5:
		return RWSMAT;
	case 6:
		return RWSDES;
	case 7:
		return RWSCAL;
	case 8:
		return RWSNUM;
	case 9:  
		return RWSMAN;
	case 10: 
		return RWSRND;
	case 11:
		return RWSRSM;
	case 12:
		return RWSRSV;
	case 13:
		return RWSCSI;
	case 14:
		return RWSCMU;
	default:
		return RWSUNK;
	}
}
function RWSGDIMon($r_mo, $r_y)
{
	switch ($r_mo) {
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
		if ($r_y % 400 == 0)
			return 29;
		else if ($r_y % 100 == 0)
			return 28;
		else if ($r_y % 4 == 0)
			return 29;
		else
			return 28;
	default:
		return FALSE;
	}
}
function RWSISRec(&$r_qiz, $r_rcd, $r_pop=FALSE)
{
	global $RWSLB;
	global $CFG;
	$r_p = 0;
	$r_sz = strlen($r_rcd);
	if (!empty($r_qiz->coursemodule)) {
		$r_ctx = get_context_instance(CONTEXT_MODULE, $r_qiz->coursemodule);
		$r_ctxi = $r_ctx->id;
	} else if (!empty($r_qiz->course)) {
		$r_ctx = get_context_instance(CONTEXT_COURSE, $r_qiz->course);
		$r_ctxi = $r_ctx->id;
	} else {
		$r_ctxi = null;
	}
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qiz->intro = trim($r_fld); 
	$r_qiz->introformat = FORMAT_HTML;
	$r_ct = 2;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("n", $r_fld);
	$r_y = $r_dat[1];
	if ($r_y != 0 && ($r_y < 1970 || $r_y > 2020))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_mo = intval($r_dat[1]);
	if ($r_y != 0 && ($r_mo < 1 || $r_mo > 12))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_da = intval($r_dat[1]);
	if ($r_y != 0 && ($r_da < 1 || $r_da > RWSGDIMon($r_mo, $r_y)))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_hr = intval($r_dat[1]);
	if ($r_y != 0 && ($r_hr < 0 || $r_hr > 23))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_mt = intval($r_dat[1]);
	if ($r_y != 0 && ($r_mt < 0 || $r_mt > 55 || $r_mt % 5 != 0))
		return FALSE;
	if ($r_y == 0)
		$r_qiz->timeopen = 0;
	else
		$r_qiz->timeopen = make_timestamp($r_y, $r_mo, $r_da, $r_hr, $r_mt);
	$r_ct = 2;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("n", $r_fld);
	$r_y = $r_dat[1];
	if ($r_y != 0 && ($r_y < 1970 || $r_y > 2020))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_mo = intval($r_dat[1]);
	if ($r_y != 0 && ($r_mo < 1 || $r_mo > 12))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_da = intval($r_dat[1]);
	if ($r_y != 0 && ($r_da < 1 || $r_da > RWSGDIMon($r_mo, $r_y)))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_hr = intval($r_dat[1]);
	if ($r_y != 0 && ($r_hr < 0 || $r_hr > 23))
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_mt = intval($r_dat[1]);
	if ($r_y != 0 && ($r_mt < 0 || $r_mt > 55 || $r_mt % 5 != 0))
		return FALSE;
	if ($r_y == 0)
		$r_qiz->timeclose = 0;
	else
		$r_qiz->timeclose = make_timestamp($r_y, $r_mo, $r_da, $r_hr, $r_mt);
	if ($r_qiz->timeopen != 0 && $r_qiz->timeclose != 0
	  && $r_qiz->timeopen > $r_qiz->timeclose)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->timelimitenable = intval($r_dat[1]);
	if ($r_qiz->timelimitenable != 0 && $r_qiz->timelimitenable != 1)
		return FALSE;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_qiz->timelimit = $r_dat[1] * 60; 
	if ($r_qiz->timelimitenable == 0)
		$r_qiz->timelimit = 0; 
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_qiz->delay1 = $r_dat[1];
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_qiz->delay2 = $r_dat[1];
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->questionsperpage = intval($r_dat[1]);
	if ($r_qiz->questionsperpage < 0 || $r_qiz->questionsperpage > 50)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->shufflequestions = intval($r_dat[1]);
	if ($r_qiz->shufflequestions != 0 && $r_qiz->shufflequestions != 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->shuffleanswers = intval($r_dat[1]);
	if ($r_qiz->shuffleanswers != 0 && $r_qiz->shuffleanswers != 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->attempts = intval($r_dat[1]);
	if ($r_qiz->attempts < 0 || $r_qiz->attempts > 10)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->attemptonlast = intval($r_dat[1]);
	if ($r_qiz->attemptonlast != 0 && $r_qiz->attemptonlast != 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_adap = intval($r_dat[1]);
	if ($r_adap != 0 && $r_adap != 1)
		return FALSE;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_qiz->grade = $r_dat[1];
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->grademethod = intval($r_dat[1]);
	switch ($r_qiz->grademethod) {
	case 1: 
	case 2: 
	case 3: 
	case 4: 
		break;
	default:
		return FALSE;
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_pen = intval($r_dat[1]);
	if ($r_pen != 0 && $r_pen != 1)
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		if ($r_adap == 0 && $r_pen == 0)
			$r_qiz->preferredbehaviour = "deferredfeedback";
		else if ($r_adap == 0 && $r_pen == 1)
			$r_qiz->preferredbehaviour = "deferredfeedback";
		else if ($r_adap == 1 && $r_pen == 0)
			$r_qiz->preferredbehaviour = "adaptivenopenalty";
		else if ($r_adap == 1 && $r_pen == 1)
			$r_qiz->preferredbehaviour = "adaptive";
		else
			return FALSE;
	}
	else { 
		$r_qiz->adaptive = $r_adap;
		$r_qiz->penaltyscheme = $r_pen;
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->decimalpoints = intval($r_dat[1]);
	switch ($r_qiz->decimalpoints) {
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
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_rim = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_aim = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_fim = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_gim = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_sim = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_oim = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_rop = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_aop = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_fop = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_gop = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_sop = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_oop = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_rcl = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_acl = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_fcl = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_gcl = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_scl = $r_stg;
	else
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_stg = intval($r_dat[1]);
	if ($r_stg == 0 || $r_stg == 1)
		$r_ocl = $r_stg;
	else
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_qiz->attemptduring = 1;
		if (!$r_qiz->attemptduring)
			unset($r_qiz->attemptduring);
		$r_qiz->correctnessduring = 1;
		if (!$r_qiz->correctnessduring)
			unset($r_qiz->correctnessduring);
		$r_qiz->marksduring = 1;
		if (!$r_qiz->marksduring)
			unset($r_qiz->marksduring);
		$r_qiz->specificfeedbackduring = $r_fim;
		if (!$r_qiz->specificfeedbackduring)
			unset($r_qiz->specificfeedbackduring);
		$r_qiz->generalfeedbackduring = $r_gim;
		if (!$r_qiz->generalfeedbackduring)
			unset($r_qiz->generalfeedbackduring);
		$r_qiz->rightanswerduring = $r_aim;
		if (!$r_qiz->rightanswerduring)
			unset($r_qiz->rightanswerduring);
		$r_qiz->overallfeedbackduring = 0;
		if (!$r_qiz->overallfeedbackduring)
			unset($r_qiz->overallfeedbackduring);
		$r_qiz->attemptimmediately = $r_rim;
		if (!$r_qiz->attemptimmediately)
			unset($r_qiz->attemptimmediately);
		$r_qiz->correctnessimmediately = $r_sim;
		if (!$r_qiz->correctnessimmediately)
			unset($r_qiz->correctnessimmediately);
		$r_qiz->marksimmediately = $r_sim;
		if (!$r_qiz->marksimmediately)
			unset($r_qiz->marksimmediately);
		$r_qiz->specificfeedbackimmediately = $r_fim;
		if (!$r_qiz->specificfeedbackimmediately)
			unset($r_qiz->specificfeedbackimmediately);
		$r_qiz->generalfeedbackimmediately = $r_gim;
		if (!$r_qiz->generalfeedbackimmediately)
			unset($r_qiz->generalfeedbackimmediately);
		$r_qiz->rightanswerimmediately = $r_aim;
		if (!$r_qiz->rightanswerimmediately)
			unset($r_qiz->rightanswerimmediately);
		$r_qiz->overallfeedbackimmediately = $r_oim;
		if (!$r_qiz->overallfeedbackimmediately)
			unset($r_qiz->overallfeedbackimmediately);
		$r_qiz->attemptopen = $r_rop;
		if (!$r_qiz->attemptopen)
			unset($r_qiz->attemptopen);
		$r_qiz->correctnessopen = $r_sop;
		if (!$r_qiz->correctnessopen)
			unset($r_qiz->correctnessopen);
		$r_qiz->marksopen = $r_sop;
		if (!$r_qiz->marksopen)
			unset($r_qiz->marksopen);
		$r_qiz->specificfeedbackopen = $r_fop;
		if (!$r_qiz->specificfeedbackopen)
			unset($r_qiz->specificfeedbackopen);
		$r_qiz->generalfeedbackopen = $r_gop;
		if (!$r_qiz->generalfeedbackopen)
			unset($r_qiz->generalfeedbackopen);
		$r_qiz->rightansweropen = $r_aop;
		if (!$r_qiz->rightansweropen)
			unset($r_qiz->rightansweropen);
		$r_qiz->overallfeedbackopen = $r_oop;
		if (!$r_qiz->overallfeedbackopen)
			unset($r_qiz->overallfeedbackopen);
		$r_qiz->attemptclosed = $r_rcl;
		if (!$r_qiz->attemptclosed)
			unset($r_qiz->attemptclosed);
		$r_qiz->correctnessclosed = $r_scl;
		if (!$r_qiz->correctnessclosed)
			unset($r_qiz->correctnessclosed);
		$r_qiz->marksclosed = $r_scl;
		if (!$r_qiz->marksclosed)
			unset($r_qiz->marksclosed);
		$r_qiz->specificfeedbackclosed = $r_fcl;
		if (!$r_qiz->specificfeedbackclosed)
			unset($r_qiz->specificfeedbackclosed);
		$r_qiz->generalfeedbackclosed = $r_gcl;
		if (!$r_qiz->generalfeedbackclosed)
			unset($r_qiz->generalfeedbackclosed);
		$r_qiz->rightanswerclosed = $r_acl;
		if (!$r_qiz->rightanswerclosed)
			unset($r_qiz->rightanswerclosed);
		$r_qiz->overallfeedbackclosed = $r_ocl;
		if (!$r_qiz->overallfeedbackclosed)
			unset($r_qiz->overallfeedbackclosed);
	}
	else { 
		$r_qiz->responsesimmediately = $r_rim;
		if (!$r_qiz->responsesimmediately)
			unset($r_qiz->responsesimmediately);
		$r_qiz->answersimmediately = $r_aim;
		if (!$r_qiz->answersimmediately)
			unset($r_qiz->answersimmediately);
		$r_qiz->feedbackimmediately = $r_fim;
		if (!$r_qiz->feedbackimmediately)
			unset($r_qiz->feedbackimmediately);
		$r_qiz->generalfeedbackimmediately = $r_gim;
		if (!$r_qiz->generalfeedbackimmediately)
			unset($r_qiz->generalfeedbackimmediately);
		$r_qiz->scoreimmediately = $r_sim;
		if (!$r_qiz->scoreimmediately)
			unset($r_qiz->scoreimmediately);
		$r_qiz->overallfeedbackimmediately = $r_oim;
		if (!$r_qiz->overallfeedbackimmediately)
			unset($r_qiz->overallfeedbackimmediately);
		$r_qiz->responsesopen = $r_rop;
		if (!$r_qiz->responsesopen)
			unset($r_qiz->responsesopen);
		$r_qiz->answersopen = $r_aop;
		if (!$r_qiz->answersopen)
			unset($r_qiz->answersopen);
		$r_qiz->feedbackopen = $r_fop;
		if (!$r_qiz->feedbackopen)
			unset($r_qiz->feedbackopen);
		$r_qiz->generalfeedbackopen = $r_gop;
		if (!$r_qiz->generalfeedbackopen)
			unset($r_qiz->generalfeedbackopen);
		$r_qiz->scoreopen = $r_sop;
		if (!$r_qiz->scoreopen)
			unset($r_qiz->scoreopen);
		$r_qiz->overallfeedbackopen = $r_oop;
		if (!$r_qiz->overallfeedbackopen)
			unset($r_qiz->overallfeedbackopen);
		$r_qiz->responsesclosed = $r_rcl;
		if (!$r_qiz->responsesclosed)
			unset($r_qiz->responsesclosed);
		$r_qiz->answersclosed = $r_acl;
		if (!$r_qiz->answersclosed)
			unset($r_qiz->answersclosed);
		$r_qiz->feedbackclosed = $r_fcl;
		if (!$r_qiz->feedbackclosed)
			unset($r_qiz->feedbackclosed);
		$r_qiz->generalfeedbackclosed = $r_gcl;
		if (!$r_qiz->generalfeedbackclosed)
			unset($r_qiz->generalfeedbackclosed);
		$r_qiz->scoreclosed = $r_scl;
		if (!$r_qiz->scoreclosed)
			unset($r_qiz->scoreclosed);
		$r_qiz->overallfeedbackclosed = $r_ocl;
		if (!$r_qiz->overallfeedbackclosed)
			unset($r_qiz->overallfeedbackclosed);
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->popup = intval($r_dat[1]);
	if ($r_qiz->popup != 0 && $r_qiz->popup != 1)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qiz->quizpassword = trim($r_fld); 
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qiz->subnet = trim($r_fld); 
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->groupmode = intval($r_dat[1]);
	switch ($r_qiz->groupmode) {
	case 0: 
	case 1: 
	case 2: 
		break;
	default:
		return FALSE;
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_qiz->visible = intval($r_dat[1]);
	if ($r_qiz->visible != 0 && $r_qiz->visible != 1)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qiz->cmidnumber = trim($r_fld); 
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_nf = intval($r_dat[1]);
	$r_fds = array();
	for ($r_i = 0; $r_i < $r_nf; $r_i++) {
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_fds[] = trim($r_fld); 
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_nb = intval($r_dat[1]);
	$r_bds = array();
	for ($r_i = 0; $r_i < $r_nb; $r_i++) {
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_bd = trim($r_fld); 
		$r_l = strlen($r_bd);
		if ($r_l == 0)
			return FALSE;
		if (is_numeric($r_bd)) {
			if ($r_bd <= 0 || $r_bd >= $r_qiz->grade)
				return FALSE;
			if ($r_i > 0 && $r_bd >= $r_lb)
				return FALSE;
			$r_lb = $r_bd;
		}
		else {
			if ($r_bd[$r_l-1] != '%')
				return FALSE;
			$r_pct = trim(substr($r_bd, 0, -1));
			if (!is_numeric($r_pct))
				return FALSE;
			if ($r_pct <= 0 || $r_pct >= 100)
				return FALSE;
			if ($r_i > 0 && $r_bd >= $r_lb)
				return FALSE;
			$r_lb = $r_bd * $r_qiz->grade / 100.0;
		}
		$r_bds[] = $r_bd;
	}
	$r_nf = count($r_fds);
	$r_nb = count($r_bds);
	if ($r_nf > 0) {
		if ($r_nf != $r_nb + 1)
			return FALSE;
		for ($r_i = 0; $r_i < $r_nf; $r_i++) {
			if (isset($r_qiz->feedbacktext[$r_i]["itemid"]))
				$r_drf = $r_qiz->feedbacktext[$r_i]["itemid"];
			else
				$r_drf = 0;
			$r_cmp = "mod_quiz";
			$r_far = "feedback";
			$r_iti = null;
			$r_op = null;
			$r_txt = $r_fds[$r_i];
			$r_qiz->feedbacktext[$r_i]["text"] = file_prepare_draft_area(
			  $r_drf, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_op, $r_txt
			  );
			$r_qiz->feedbacktext[$r_i]["format"] = FORMAT_HTML;
			$r_qiz->feedbacktext[$r_i]["itemid"] = $r_drf;
			if ($r_i < $r_nf - 1)
				$r_qiz->feedbackboundaries[$r_i] = $r_bds[$r_i];
		}
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_lbq = intval($r_dat[1]);
	if ($r_lbq != 0 && $r_lbq != 1)
		return FALSE;
	$RWSLB->atts = $r_lbq;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_lbr = intval($r_dat[1]);
	if ($r_lbr != 0 && $r_lbr != 1)
		return FALSE;
	$RWSLB->revs = $r_lbr;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$RWSLB->pw = trim($r_fld); 
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	if ($r_pop) {
		if (is_null($r_qiz->quizpassword) && !is_null($r_qiz->password))
			$r_qiz->quizpassword = $r_qiz->password;
		quiz_process_options($r_qiz);
	}
	return TRUE;
}
function RWSSLBSet(&$r_qiz)
{
	global $RWSLB;
	$RWSLB->perr = FALSE;
	if ($RWSLB->mok) {
		$r_ok = lockdown_set_settings($r_qiz->instance, $RWSLB->atts,
		  $RWSLB->revs, $RWSLB->pw);
		if (!$r_ok)
			$RWSLB->perr = TRUE;
	} else if ($RWSLB->bok) {
		$r_upq = FALSE;
		if ($RWSLB->atts == 1) {
			$r_ok = lockdown_set_quiz_options($r_qiz->instance);
			if (!$r_ok)
				$RWSLB->perr = TRUE;
			if ($r_ok) {
				$r_qiz->name .= get_string("requires_ldb",
				  "block_lockdownbrowser");
				$r_upq = TRUE;
			}
		} else {
			$r_rcd = lockdown_get_quiz_options($r_qiz->instance);
			if ($r_rcd !== FALSE) {
				lockdown_delete_options($r_qiz->instance);
				$r_suf = get_string("requires_ldb", "block_lockdownbrowser");
				$r_qiz->name = str_replace($r_suf, "", $r_qzn);
				$r_upq = TRUE;
			}
		}
		if ($r_upq) {
			if (is_null($r_qiz->quizpassword) && !is_null($r_qiz->password))
				$r_qiz->quizpassword = $r_qiz->password;
			$r_res = quiz_update_instance($r_qiz);
			if (!$r_res || is_string($r_res))
				$RWSLB->perr = TRUE;
		}
	} 
}
function RWSIARec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $USER;
	if (RWSGQRType($r_rcd) != RWSATT)
		return FALSE;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ff = $r_fld; 
	$r_ff = clean_filename($r_ff);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_fn = $r_fld; 
	$r_fn = clean_filename($r_fn);
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_fdat = $r_fld; 
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_ctxi = $r_ctx->id;
	$r_cmp = "mod_respondusws";
	$r_far = "upload";
	$r_iti = $USER->id;
	$r_fpt = "/$r_ff/";
	$r_fna = $r_fn;
	$r_finf = array(
	  "contextid" => $r_ctxi, "component" => $r_cmp,
	  "filearea" => $r_far, "itemid" => $r_iti,
	  "filepath" => $r_fpt, "filename" => $r_fna
	  );
	$r_crpth = "$r_ff/$r_fn";
	try {
		$r_fs = get_file_storage();
		$r_fex = $r_fs->file_exists(
		  $r_ctxi, $r_cmp, $r_far, $r_iti, $r_fpt, $r_fna
		  );
		if ($r_fex)
			return FALSE;
		if (!$r_fs->create_file_from_string($r_finf, $r_fdat))
			return FALSE;
	} catch (Exception $r_e) {
		return FALSE;
	}
	return $r_crpth;
}
function RWSIRRec($r_cid, $r_qci, $r_rcd)
{
	if (RWSGQRType($r_rcd) != RWSRSV)
		return FALSE;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	return TRUE;
}
function RWSISARec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGQRType($r_rcd) != RWSSHA)
		return FALSE;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSSHA;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = $r_dat[1];
	else
		$r_qst->defaultgrade = $r_dat[1];
	$r_ct = 8;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->penalty = RWSDblIn($r_fld);
	if ($r_qst->penalty < 0 || $r_qst->penalty > 1)
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($r_qst->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$r_qst->penalty = "0.3333333";
			break;
		}
	}
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_op = new stdClass();
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_op->usecase = intval($r_dat[1]);
	if ($r_op->usecase != 0 && $r_op->usecase != 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_na = intval($r_dat[1]);
	if ($r_na < 1)
		return FALSE;
	$r_asrs = array();
	$r_mf = -1;
	for ($r_i = 0; $r_i < $r_na; $r_i++) {
		$r_asr = new stdClass();
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_asr->answer = trim($r_fld); 
		$r_asr->answerformat = FORMAT_PLAIN;
		$r_asr->answer = clean_param($r_asr->answer, PARAM_RAW);
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_asr->fraction = strval(RWSDblIn($r_fld));
		switch ($r_asr->fraction) {
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
				if (RWSFCmp($r_bv, 2011020100, 2) >= 0)
					$r_asr->fraction = "0";
				break;
		}
		if (RWSFCmp($r_bv, 2011020100, 2) == -1) {
			switch ($r_asr->fraction) { 
				case "0.83333":
					$r_asr->fraction = "0.8333333";
					break;
				case "0.66666":
					$r_asr->fraction = "0.6666667";
					break;
				case "0.33333":
					$r_asr->fraction = "0.3333333";
					break;
				case "0.16666":
					$r_asr->fraction = "0.1666667";
					break;
				case "0.142857":
					$r_asr->fraction = "0.1428571";
					break;
				case "0.11111":
					$r_asr->fraction = "0.1111111";
					break;
				default:
					$r_asr->fraction = "0";
					break;
			}
		}
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_asr->feedback = trim($r_fld); 
		$r_asr->feedbackformat = FORMAT_HTML;
		$r_asr->feedback = clean_param($r_asr->feedback, PARAM_RAW);
		if (strlen($r_asr->answer) == 0)
			continue;
		$r_asrs[] = $r_asr;
		if ($r_asr->fraction > $r_mf)
			$r_mf = $r_asr->fraction;
	}
	if (count($r_asrs) < 1)
		return FALSE;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	$r_aid = array();
	foreach ($r_asrs as $r_an) {
		$r_an->question = $r_qst->id;
		$r_an->id = $DB->insert_record("question_answers", $r_an);
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_an->id;
		$r_txt = $r_an->feedback;
		$r_an->feedback = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question_answers", $r_an);
		$r_aid[] = $r_an->id;
	}
	$r_op->question = $r_qst->id;
	$r_op->answers = implode(",", $r_aid);
	$r_op->id = $DB->insert_record("question_shortanswer", $r_op);
	return $r_qst->id;
}
function RWSITFRec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGQRType($r_rcd) != RWSTRF)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSTRF;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = $r_dat[1];
	else
		$r_qst->defaultgrade = $r_dat[1];
	$r_ct = 8;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->penalty = RWSDblIn($r_fld);
	if ($r_qst->penalty != 1) 
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_tru = new stdClass();
	$r_tru->answer = get_string("true", "quiz");
	$r_fal = new stdClass();
	$r_fal->answer = get_string("false", "quiz");
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_cor = intval($r_dat[1]);
	if ($r_cor != 0 && $r_cor != 1)
		return FALSE;
	$r_tru->fraction = $r_cor;
	$r_fal->fraction = 1 - $r_cor;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_tru->feedback = trim($r_fld); 
	$r_tru->feedbackformat = FORMAT_HTML;
	$r_tru->feedback = clean_param($r_tru->feedback, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_fal->feedback = trim($r_fld); 
	$r_fal->feedbackformat = FORMAT_HTML;
	$r_fal->feedback = clean_param($r_fal->feedback, PARAM_RAW);
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	$r_tru->question = $r_qst->id;
	$r_tru->id = $DB->insert_record("question_answers", $r_tru);
	$r_cmp = "question";
	$r_far = "answerfeedback";
	$r_iti = $r_tru->id;
	$r_txt = $r_tru->feedback;
	$r_tru->feedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question_answers", $r_tru);
	$r_fal->question = $r_qst->id;
	$r_fal->id = $DB->insert_record("question_answers", $r_fal);
	$r_cmp = "question";
	$r_far = "answerfeedback";
	$r_iti = $r_fal->id;
	$r_txt = $r_fal->feedback;
	$r_fal->feedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question_answers", $r_fal);
	$r_op = new stdClass();
	$r_op->question = $r_qst->id;
	$r_op->trueanswer = $r_tru->id;
	$r_op->falseanswer = $r_fal->id;
	$r_op->id = $DB->insert_record("question_truefalse", $r_op);
	return $r_qst->id;
}
function RWSIMARec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGQRType($r_rcd) != RWSMAN)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSMAN;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 8;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->penalty = RWSDblIn($r_fld);
	if ($r_qst->penalty < 0 || $r_qst->penalty > 1)
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($r_qst->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$r_qst->penalty = "0.3333333";
			break;
		}
	}
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_chn = array();
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = 0;
	else
		$r_qst->defaultgrade = 0;
	$r_clzf = RWSGCFields($r_qst->questiontext);
	if ($r_clzf === FALSE)
		return FALSE;
	$r_chc = count($r_clzf);
	for ($r_i = 0; $r_i < $r_chc; $r_i++) {
		$r_chd = RWSCCChild($r_qst, $r_clzf[$r_i]);
		if ($r_chd === FALSE)
			return FALSE;
		$r_chn[] = $r_chd;
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
			$r_qst->defaultmark += $r_chd->defaultmark;
		else
			$r_qst->defaultgrade += $r_chd->defaultgrade;
		$r_pk = $r_i+1;
		$r_qst->questiontext = implode("{#$r_pk}",
		  explode($r_clzf[$r_i], $r_qst->questiontext, 2));
	}
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	$r_chid = array();
	foreach ($r_chn as $r_chd) {
		$r_chd->parent = $r_qst->id;
		$r_chd->parent_qtype = $r_qst->qtype;
		$r_chd->id = RWSCChild($r_chd, $r_cid, $r_ctxi);
		if ($r_chd->id === FALSE) {
			if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
				question_delete_question($r_qst->id);
			else
				delete_question($r_qst->id);
			return FALSE;
		}
		$r_chid[] = $r_chd->id;
	}
	if (count($r_chid) > 0) {
		$r_op = new stdClass();
		$r_op->question = $r_qst->id;
		$r_op->sequence = implode(",", $r_chid);
		$r_op->id = $DB->insert_record("question_multianswer", $r_op);
	}
	return $r_qst->id;
}
function RWSCCChild($r_qst, $r_fld)
{
	global $CFG;
	global $RWSPFNAME;
	$r_rxpt = FALSE;
	$r_qtn = get_list_of_plugins("question/type");
	if (count($r_qtn) > 0) {
		foreach ($r_qtn as $r_qn) {
			if (strcasecmp($r_qn, RWSRXP) == 0) {
				$r_rxpt = TRUE;
				break;
			}
		}
	}
	$r_rxpc = FALSE;
	$r_pth = "$CFG->dirroot/question/type/multianswer/questiontype.php";
	$r_dat = file_get_contents($r_pth);
	if ($r_dat !== FALSE
	  && strpos($r_dat, "ANSWER_REGEX_ANSWER_TYPE_REGEXP") !== FALSE)
		$r_rxpc = TRUE;
	$r_rxps = ($r_rxpt && $r_rxpc);
	$r_chd = new stdClass();
	$r_chd->name = $r_qst->name; 
	$r_chd->category = $r_qst->category;
	$r_chd->questiontext = $r_fld;
	$r_chd->questiontextformat = $r_qst->questiontextformat;
	$r_chd->questiontext = clean_param($r_chd->questiontext, PARAM_RAW);
	$r_chd->answer = array();
	$r_chd->answerformat = array();
	$r_chd->fraction = array();
	$r_chd->feedback = array();
	$r_chd->feedbackformat = array();
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_chd->defaultmark = 1;
	else
		$r_chd->defaultgrade = 1;
	$r_st = 1;
	$r_ofs = strpos(substr($r_fld, $r_st), ":");
	if ($r_ofs === FALSE)
		return FALSE;
	if ($r_ofs > 0) {
		$r_sbf = trim(substr($r_fld, $r_st, $r_ofs));
		if (strlen($r_sbf) > 0 && is_numeric($r_sbf)) {
			if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
				$r_chd->defaultmark = floatval($r_sbf);
			else
				$r_chd->defaultgrade = floatval($r_sbf);
		}
	}
	$r_st += $r_ofs;
	$r_sbf = substr($r_fld, $r_st);
	if (strncmp($r_sbf, ":NUMERICAL:", 11) == 0
	  || strncmp($r_sbf, ":NM:", 4) == 0) {
        $r_chd->qtype = RWSNUM;
		$r_chd->tolerance = array();
        $r_chd->multiplier = array();
        $r_chd->units = array();
		$r_chd->instructions = "";
		$r_chd->instructionsformat = FORMAT_HTML;
	} else if (strncmp($r_sbf, ":SHORTANSWER:", 13) == 0
	  || strncmp($r_sbf, ":SA:", 4) == 0
	  || strncmp($r_sbf, ":MW:", 4) == 0) {
        $r_chd->qtype = RWSSHA;
		$r_chd->usecase = 0;
	} else if (strncmp($r_sbf, ":SHORTANSWER_C:", 15) == 0
	  || strncmp($r_sbf, ":SAC:", 5) == 0
	  || strncmp($r_sbf, ":MWC:", 5) == 0) {
        $r_chd->qtype = RWSSHA;
		$r_chd->usecase = 1;
	} else if (strncmp($r_sbf, ":MULTICHOICE:", 13) == 0
	  || strncmp($r_sbf, ":MC:", 4) == 0) {
        $r_chd->qtype = RWSMCH;
		$r_chd->single = 1;
		$r_chd->answernumbering = 0;
		$r_chd->shuffleanswers = 1;
		$r_chd->correctfeedback = "";
		$r_chd->correctfeedbackformat = FORMAT_HTML;
		$r_chd->partiallycorrectfeedback = "";
		if (strlen($RWSPFNAME) > 0)
			$r_chd->$RWSPFNAME = FORMAT_HTML;
		$r_chd->incorrectfeedback = "";
		$r_chd->incorrectfeedbackformat = FORMAT_HTML;
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
			$r_chd->shownumcorrect = 0;
		$r_chd->layout = 0;
	} else if (strncmp($r_sbf, ":MULTICHOICE_V:", 15) == 0
	  || strncmp($r_sbf, ":MCV:", 5) == 0) {
        $r_chd->qtype = RWSMCH;
		$r_chd->single = 1;
		$r_chd->answernumbering = 0;
		$r_chd->shuffleanswers = 1;
		$r_chd->correctfeedback = "";
		$r_chd->correctfeedbackformat = FORMAT_HTML;
		$r_chd->partiallycorrectfeedback = "";
		if (strlen($RWSPFNAME) > 0)
			$r_chd->$RWSPFNAME = FORMAT_HTML;
		$r_chd->incorrectfeedback = "";
		$r_chd->incorrectfeedbackformat = FORMAT_HTML;
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
			$r_chd->shownumcorrect = 0;
		$r_chd->layout = 1;
	} else if (strncmp($r_sbf, ":MULTICHOICE_H:", 15) == 0
	  || strncmp($r_sbf, ":MCH:", 5) == 0) {
        $r_chd->qtype = RWSMCH;
		$r_chd->single = 1;
		$r_chd->answernumbering = 0;
		$r_chd->shuffleanswers = 1;
		$r_chd->correctfeedback = "";
		$r_chd->correctfeedbackformat = FORMAT_HTML;
		$r_chd->partiallycorrectfeedback = "";
		if (strlen($RWSPFNAME) > 0)
			$r_chd->$RWSPFNAME = FORMAT_HTML;
		$r_chd->incorrectfeedback = "";
		$r_chd->incorrectfeedbackformat = FORMAT_HTML;
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
			$r_chd->shownumcorrect = 0;
		$r_chd->layout = 2;
	} else if ($r_rxps
	  && strncmp($r_sbf, ":REGEXP:", 8) == 0) {
        $r_chd->qtype = RWSRXP;
        $r_chd->usehint = 0;
	} else {
		return FALSE;
	}
	$r_st++;
	$r_ofs = strpos(substr($r_fld, $r_st), ":");
	$r_st += $r_ofs;
	$r_st++;
	$r_fln = strlen($r_fld);
	while ($r_st < $r_fln) {
		if ($r_fld[$r_st] == '}') { 
			break;
		}
		if ($r_fld[$r_st] == '~') { 
			$r_st++;
		}
		$r_fra = "0";
		if ($r_fld[$r_st] == '=') { 
			$r_fra = "1";
			$r_st++;
		}
		if ($r_fld[$r_st] == '%') { 
			$r_st++;
			$r_pct = "";
			while ($r_st < $r_fln) {
				if ($r_fld[$r_st] == '%')
					break;
				$r_pct .= $r_fld[$r_st];
				$r_st++;
			}
			$r_pct = trim($r_pct);
			if (strlen($r_pct) == 0 || !ctype_digit($r_pct))
				return FALSE;
			$r_fra = .01 * $r_pct;
			$r_st++;
		}
		$r_asr = "";
		if ($r_chd->qtype == RWSNUM) {
			$r_tol = "";
			$r_fnd = FALSE;
			while ($r_st < $r_fln) {
				if ($r_fld[$r_st] == '#'
				  || $r_fld[$r_st] == '~'
				  || $r_fld[$r_st] == '}') {
					break;
				} else if ($r_fld[$r_st] == ':') {
					$r_fnd = TRUE;
					$r_st++;
					continue;
				}
				if ($r_fnd)
					$r_tol .= $r_fld[$r_st];
				else
					$r_asr .= $r_fld[$r_st];
				$r_st++;
			}
			$r_asr = trim($r_asr);
			if (strlen($r_asr) == 0)
				return FALSE;
			if (($r_asr != strval(floatval($r_asr))) && $r_asr != "*")
				return FALSE;
			$r_asr = clean_param($r_asr, PARAM_RAW);
			$r_tol = trim($r_tol);
			if (strlen($r_tol) == 0
			  || ($r_tol != strval(floatval($r_tol)))
			  || $r_asr == "*")
				$r_tol = 0;
		} else { 
			$r_itg = FALSE;
			while ($r_st < $r_fln) {
				if ($r_fld[$r_st] == '<')
					$r_itg = TRUE;
				else if ($r_fld[$r_st] == '>')
					$r_itg = FALSE;
				else if (!$r_itg &&
				  ($r_fld[$r_st] == '#'
					|| $r_fld[$r_st] == '~'
					|| $r_fld[$r_st] == '}')) {
					$r_st--;
					$r_esc = ($r_fld[$r_st] == '\\');
					$r_st++;
					if (!$r_esc)
						break;
				}
				$r_asr .= $r_fld[$r_st];
				$r_st++;
			}
			$r_asr = trim($r_asr);
			if (strlen($r_asr) == 0)
				return FALSE;
			$r_asr = str_replace("\#", "#", $r_asr);
			$r_asr = str_replace("\}", "}", $r_asr);
			$r_asr = str_replace("\~", "~", $r_asr);
			$r_asr = clean_param($r_asr, PARAM_RAW);
		}
		$r_fb = "";
		if ($r_fld[$r_st] == '#') { 
			$r_st++;
			$r_fb = "";
			$r_itg = FALSE;
			while ($r_st < $r_fln) {
				if ($r_fld[$r_st] == '<')
					$r_itg = TRUE;
				else if ($r_fld[$r_st] == '>')
					$r_itg = FALSE;
				else if (!$r_itg &&
				  ($r_fld[$r_st] == '~'
					|| $r_fld[$r_st] == '}')) {
					$r_st--;
					$r_esc = ($r_fld[$r_st] == '\\');
					$r_st++;
					if (!$r_esc)
						break;
				}
				$r_fb .= $r_fld[$r_st];
				$r_st++;
			}
			$r_fb = trim($r_fb);
			$r_fb = str_replace("\#", "#", $r_fb);
			$r_fb = str_replace("\}", "}", $r_fb);
			$r_fb = str_replace("\~", "~", $r_fb);
			$r_fb = clean_param($r_fb, PARAM_RAW);
		}
		$r_chd->answer[] = $r_asr;
		if ($r_chd->qtype == RWSNUM
		  || $r_chd->qtype == RWSSHA
		  || $r_chd->qtype == RWSRXP)
			$r_chd->answerformat[] = FORMAT_PLAIN;
		else
			$r_chd->answerformat[] = FORMAT_HTML;
		$r_chd->fraction[] = $r_fra;
		$r_chd->feedback[] = $r_fb;
		$r_chd->feedbackformat[] = FORMAT_HTML;
		if ($r_chd->qtype == RWSNUM)
			$r_chd->tolerance[] = $r_tol;
	}
	$r_na = count($r_chd->answer);
	if ($r_na == 0)
		return FALSE;
	if (count($r_chd->fraction) != $r_na)
		return FALSE;
	if (count($r_chd->feedback) != $r_na)
		return FALSE;
	if ($r_chd->qtype == RWSNUM && count($r_chd->tolerance) != $r_na)
		return FALSE;
	return $r_chd;
}
function RWSGCFields($r_qstx)
{
	$r_p = 0;
	$r_l = strlen($r_qstx);
	$r_itg = FALSE;
	$r_ifd = FALSE;
	$r_flds = array();
	while ($r_p < $r_l) {
		if ($r_qstx[$r_p] == '<')
			$r_itg = TRUE;
		else if ($r_qstx[$r_p] == '>')
			$r_itg = FALSE;
		else if (!$r_ifd && !$r_itg && $r_qstx[$r_p] == '{') {
			$r_esc = FALSE;
			if ($r_p > 0) {
				$r_p--;
				$r_esc = ($r_qstx[$r_p] == '\\');
				$r_p++;
			}
			if (!$r_esc) {
				$r_fld = "";
				$r_ifd = TRUE;
			}
		}
		else if ($r_ifd && !$r_itg && $r_qstx[$r_p] == '}') {
			$r_p--;
			$r_esc = ($r_qstx[$r_p] == '\\');
			$r_p++;
			if (!$r_esc) {
				$r_fld .= $r_qstx[$r_p];
				$r_flds[] = $r_fld;
				$r_ifd = FALSE;
			}
		}		
		if ($r_ifd)
			$r_fld .= $r_qstx[$r_p];
		$r_p++;
	}
	return $r_flds;
}
function RWSCChild($r_chd, $r_cid, $r_ctxi)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWSPFNAME;
	$r_chd->hidden = 0;
	$r_chd->length = 1;
	$r_chd->stamp = make_unique_id_code();
	$r_chd->createdby = $USER->id;
	$r_chd->modifiedby = $USER->id;
	$r_chd->penalty = 0;
	$r_chd->generalfeedback = "";
	$r_chd->generalfeedbackformat = FORMAT_HTML;
	$r_chd->timecreated = time();
	$r_chd->timemodified = time();
	if ($r_chd->qtype == RWSNUM) {
		$r_chd->id = $DB->insert_record("question", $r_chd);
		$r_cmp = "question";
		$r_far = "questiontext";
		$r_iti = $r_chd->id;
		$r_txt = $r_chd->questiontext;
		$r_chd->questiontext = RWSPAtt($r_chd->parent_qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question", $r_chd);
		$r_h = question_hash($r_chd);
		$DB->set_field("question", "version", $r_h,
		  array("id" => $r_chd->id));
		$r_na = count($r_chd->answer);
		for ($r_i = 0; $r_i < $r_na; $r_i++) {
			$r_an = new stdClass();
			$r_an->answer = $r_chd->answer[$r_i]; 
			$r_an->answerformat = $r_chd->answerformat[$r_i];
			$r_an->fraction = $r_chd->fraction[$r_i];
			$r_an->feedback = $r_chd->feedback[$r_i];
			$r_an->feedbackformat = $r_chd->feedbackformat[$r_i];
			$r_an->question = $r_chd->id;
			$r_an->id = $DB->insert_record("question_answers", $r_an);
			$r_cmp = "question";
			$r_far = "answerfeedback";
			$r_iti = $r_an->id;
			$r_txt = $r_an->feedback;
			$r_an->feedback = RWSPAtt($r_chd->parent_qtype,
			  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
			  );
			$DB->update_record("question_answers", $r_an);
			$r_op = new stdClass();
			$r_op->question = $r_chd->id;
			$r_op->answer = $r_an->id;
			$r_op->tolerance = $r_chd->tolerance[$r_i]; 
			$r_op->id = $DB->insert_record("question_numerical", $r_op);
		}
	} else if ($r_chd->qtype == RWSSHA) {
		$r_chd->id = $DB->insert_record("question", $r_chd);
		$r_cmp = "question";
		$r_far = "questiontext";
		$r_iti = $r_chd->id;
		$r_txt = $r_chd->questiontext;
		$r_chd->questiontext = RWSPAtt($r_chd->parent_qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question", $r_chd);
		$r_h = question_hash($r_chd);
		$DB->set_field("question", "version", $r_h,
		  array("id" => $r_chd->id));
		$r_aid = array();
		$r_na = count($r_chd->answer);
		for ($r_i = 0; $r_i < $r_na; $r_i++) {
			$r_an = new stdClass();
			$r_an->answer = $r_chd->answer[$r_i];
			$r_an->answerformat = $r_chd->answerformat[$r_i];
			$r_an->fraction = $r_chd->fraction[$r_i];
			$r_an->feedback = $r_chd->feedback[$r_i];
			$r_an->feedbackformat = $r_chd->feedbackformat[$r_i];
			$r_an->question = $r_chd->id;
			$r_an->id = $DB->insert_record("question_answers", $r_an);
			$r_cmp = "question";
			$r_far = "answerfeedback";
			$r_iti = $r_an->id;
			$r_txt = $r_an->feedback;
			$r_an->feedback = RWSPAtt($r_chd->parent_qtype,
			  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
			  );
			$DB->update_record("question_answers", $r_an);
			$r_aid[] = $r_an->id;
		}
		$r_op = new stdClass();
		$r_op->usecase = $r_chd->usecase;
		$r_op->question = $r_chd->id;
		$r_op->answers = implode(",", $r_aid);
		$r_op->id = $DB->insert_record("question_shortanswer", $r_op);
	} else if ($r_chd->qtype == RWSMCH) {
		$r_chd->id = $DB->insert_record("question", $r_chd);
		$r_cmp = "question";
		$r_far = "questiontext";
		$r_iti = $r_chd->id;
		$r_txt = $r_chd->questiontext;
		$r_chd->questiontext = RWSPAtt($r_chd->parent_qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question", $r_chd);
		$r_h = question_hash($r_chd);
		$DB->set_field("question", "version", $r_h,
		  array("id" => $r_chd->id));
		$r_aid = array();
		$r_na = count($r_chd->answer);
		for ($r_i = 0; $r_i < $r_na; $r_i++) {
			$r_an = new stdClass();
			$r_an->answer = $r_chd->answer[$r_i];
			$r_an->answerformat = $r_chd->answerformat[$r_i];
			$r_an->fraction = $r_chd->fraction[$r_i];
			$r_an->feedback = $r_chd->feedback[$r_i];
			$r_an->feedbackformat = $r_chd->feedbackformat[$r_i];
			$r_an->question = $r_chd->id;
			$r_an->id = $DB->insert_record("question_answers", $r_an);
			$r_cmp = "question";
			$r_far = "answer";
			$r_iti = $r_an->id;
			$r_txt = $r_an->answer;
			$r_an->answer = RWSPAtt($r_chd->parent_qtype,
			  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
			  );
			$r_cmp = "question";
			$r_far = "answerfeedback";
			$r_iti = $r_an->id;
			$r_txt = $r_an->feedback;
			$r_an->feedback = RWSPAtt($r_chd->parent_qtype,
			  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
			  );
			$DB->update_record("question_answers", $r_an);
			$r_aid[] = $r_an->id;
		}
		$r_op = new stdClass();
		$r_op->question = $r_chd->id;
		$r_op->answers = implode(",", $r_aid);
		$r_op->single = $r_chd->single;
		$r_op->answernumbering = $r_chd->answernumbering;
		$r_op->shuffleanswers = $r_chd->shuffleanswers;
		$r_op->correctfeedback = $r_chd->correctfeedback;
		$r_op->partiallycorrectfeedback = $r_chd->partiallycorrectfeedback;
		$r_op->incorrectfeedback = $r_chd->incorrectfeedback;
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
			$r_op->shownumcorrect = $r_chd->shownumcorrect;
		$r_op->layout = $r_chd->layout;
		$r_op->id = $DB->insert_record("question_multichoice", $r_op);
	} else if ($r_chd->qtype == RWSRXP) {
		$r_chd->id = $DB->insert_record("question", $r_chd);
		$r_h = question_hash($r_chd);
		$r_cmp = "question";
		$r_far = "questiontext";
		$r_iti = $r_chd->id;
		$r_txt = $r_chd->questiontext;
		$r_chd->questiontext = RWSPAtt($r_chd->parent_qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question", $r_chd);
		$DB->set_field("question", "version", $r_h,
		  array("id" => $r_chd->id));
		$r_aid = array();
		$r_na = count($r_chd->answer);
		for ($r_i = 0; $r_i < $r_na; $r_i++) {
			$r_an = new stdClass();
			$r_an->answer = $r_chd->answer[$r_i];
			$r_an->answerformat = $r_chd->answerformat[$r_i];
			$r_an->fraction = $r_chd->fraction[$r_i];
			$r_an->feedback = $r_chd->feedback[$r_i];
			$r_an->feedbackformat = $r_chd->feedbackformat[$r_i];
			$r_an->question = $r_chd->id;
			$r_an->id = $DB->insert_record("question_answers", $r_an);
			$r_cmp = "question";
			$r_far = "answerfeedback";
			$r_iti = $r_an->id;
			$r_txt = $r_an->feedback;
			$r_an->feedback = RWSPAtt($r_chd->parent_qtype,
			  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
			  );
			$DB->update_record("question_answers", $r_an);
			$r_aid[] = $r_an->id;
		}
		$r_op = new stdClass();
		$r_op->question = $r_chd->id;
		$r_op->answers = implode(",", $r_aid);
		$r_op->id = $DB->insert_record("question_regexp", $r_op);
	} else {
		return FALSE;
	}
	return $r_chd->id;
}
function RWSICRec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWSPFNAME;
	if (RWSGQRType($r_rcd) != RWSCAL)
		return FALSE;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSCAL;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = $r_dat[1];
	else
		$r_qst->defaultgrade = $r_dat[1];
	$r_ct = 8;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->penalty = RWSDblIn($r_fld);
	if ($r_qst->penalty < 0 || $r_qst->penalty > 1)
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($r_qst->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$r_qst->penalty = "0.3333333";
			break;
		}
	}
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_na = intval($r_dat[1]);
	if ($r_na != 1)
		return FALSE;
	$r_asrs = array();
	$r_tf = 0;
	for ($r_i = 0; $r_i < $r_na; $r_i++) {
		$r_an = new stdClass();
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_an->formula = trim($r_fld); 
		if (strlen($r_an->formula) == 0)
			return FALSE;
		if (!RWSCFSyn($r_an->formula))
			return FALSE;
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_an->fraction = strval(RWSDblIn($r_fld));
		switch ($r_an->fraction) {
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
				if (RWSFCmp($r_bv, 2011020100, 2) >= 0)
					$r_asr->fraction = "0";
				break;
		}
		if (RWSFCmp($r_bv, 2011020100, 2) == -1) {
			switch ($r_asr->fraction) { 
				case "0.83333":
					$r_asr->fraction = "0.8333333";
					break;
				case "0.66666":
					$r_asr->fraction = "0.6666667";
					break;
				case "0.33333":
					$r_asr->fraction = "0.3333333";
					break;
				case "0.16666":
					$r_asr->fraction = "0.1666667";
					break;
				case "0.142857":
					$r_asr->fraction = "0.1428571";
					break;
				case "0.11111":
					$r_asr->fraction = "0.1111111";
					break;
				default:
					$r_asr->fraction = "0";
					break;
			}
		}
		if ($r_an->fraction != "1")
			return FALSE;
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_an->feedback = trim($r_fld); 
		$r_an->feedbackformat = FORMAT_HTML;
		$r_an->feedback = clean_param($r_an->feedback, PARAM_RAW);
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_an->tolerance = RWSDblIn($r_fld);
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_an->tolerancetype = intval($r_dat[1]);
		switch ($r_an->tolerancetype) {
		case 1: 
		case 2: 
		case 3: 
			break;
		default:
			return FALSE;
		}
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_an->correctanswerlength = intval($r_dat[1]);
		if ($r_an->correctanswerlength < 0 || $r_an->correctanswerlength > 9)
			return FALSE;
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_an->correctanswerformat = intval($r_dat[1]);
		switch ($r_an->correctanswerformat) {
		case 1: 
		case 2: 
			break;
		default:
			return FALSE;
		}
		$r_asrs[] = $r_an;
		$r_tf += $r_an->fraction;
	}
	if (count($r_asrs) != 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_nu = intval($r_dat[1]);
	if ($r_nu < 0 || $r_nu > 1)
		return FALSE;
	$r_uts = array();
	$r_fbu = FALSE;
	for ($r_i = 0; $r_i < $r_nu; $r_i++) {
		$r_ut = new stdClass();
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_ut->name = trim($r_fld); 
		if (strlen($r_ut->name) == 0)
			return FALSE;
		$r_ut->name = clean_param($r_ut->name, PARAM_NOTAGS);
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_ut->multiplier = RWSDblIn($r_fld);
		if (RWSFCmp($r_ut->multiplier, 1, 1) == 0)
			$r_fbu = TRUE;
		else 
			return FALSE;
		$r_uts[] = $r_ut;
	}
	if (count($r_uts) > 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_nd = intval($r_dat[1]);
	if ($r_nd < 1)
		return FALSE;
	$r_dset = array();
	for ($r_i = 0; $r_i < $r_nd; $r_i++) {
		$r_ds = new stdClass();
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_ds->name = trim($r_fld); 
		if (strlen($r_ds->name) == 0)
			return FALSE;
		$r_ds->name = clean_param($r_ds->name, PARAM_NOTAGS);
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_ds->distribution = trim($r_fld); 
		switch ($r_ds->distribution) {
		case "uniform":
		case "loguniform":
			break;
		default:
			return FALSE;
		}
		if ($r_ds->distribution != "uniform")
			return FALSE;
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_ds->min = RWSDblIn($r_fld);
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_ds->max = RWSDblIn($r_fld);
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_ds->precision = intval($r_dat[1]);
		if ($r_ds->precision < 0 || $r_ds->precision > 10)
			return FALSE;
		if (RWSFCmp($r_ds->max, $r_ds->min, $r_ds->precision) < 0)
			return FALSE;
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_ds->type = intval($r_dat[1]);
		if ($r_ds->type != 1)
			return FALSE;
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_ds->status = intval($r_dat[1]);
		if ($r_ds->status != 0 && $r_ds->status != 1)
			return FALSE;
		$r_ct = 1;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_dat = unpack("C", $r_fld);
		$r_ds->itemcount = intval($r_dat[1]);
		if ($r_ds->itemcount < 1)
			return FALSE;
		$r_ds->items = array();
		$r_map = array_fill(1, $r_ds->itemcount, 0);
		for ($r_j = 0; $r_j < $r_ds->itemcount; $r_j++) {
			$r_it = new stdClass();
			$r_ct = 1;
			if ($r_sz < $r_ct)
				return FALSE;
			$r_fld = substr($r_rcd, $r_p, $r_ct);
			$r_p += $r_ct;
			$r_sz -= $r_ct;
			$r_dat = unpack("C", $r_fld);
			$r_it->itemnumber = intval($r_dat[1]);
			if ($r_it->itemnumber < 1 || $r_it->itemnumber > $r_ds->itemcount)
				return FALSE;
			if ($r_map[$r_it->itemnumber] == 1) 
				return FALSE;
			$r_map[$r_it->itemnumber] = 1;
			$r_ct = 8;
			if ($r_sz < $r_ct)
				return FALSE;
			$r_fld = substr($r_rcd, $r_p, $r_ct);
			$r_p += $r_ct;
			$r_sz -= $r_ct;
			$r_it->value = RWSDblIn($r_fld);
			$r_ds->items[] = $r_it;
		}
		if (array_sum($r_map) != $r_ds->itemcount)
			return FALSE;
		$r_dset[] = $r_ds;
	}
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	$r_op = new stdClass();
	$r_op->question = $r_qst->id;
    $r_op->synchronize = 0;
    $r_op->single = 0;
    $r_op->answernumbering = "abc";
    $r_op->shuffleanswers = 0;
    $r_op->correctfeedback = "";
    $r_op->correctfeedbackformat = FORMAT_HTML;
    $r_op->partiallycorrectfeedback = "";
    if (strlen($RWSPFNAME) > 0)
		$r_op->$RWSPFNAME = FORMAT_HTML;
    $r_op->incorrectfeedback = "";
    $r_op->incorrectfeedbackformat = FORMAT_HTML;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_op->shownumcorrect = 0;
	$r_op->id = $DB->insert_record("question_calculated_options", $r_op);
	foreach ($r_asrs as $a) {
		$r_an = new stdClass();
		$r_an->answer = $a->formula;
		$r_an->fraction = $a->fraction;
		$r_an->feedback = $a->feedback;
		$r_an->feedbackformat = $a->feedbackformat;
		$r_an->question = $r_qst->id;
		$r_an->id = $DB->insert_record("question_answers", $r_an);
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_an->id;
		$r_txt = $r_an->feedback;
		$r_an->feedback = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question_answers", $r_an);
		$r_o = new stdClass();
		$r_o->tolerance = $a->tolerance;
		$r_o->tolerancetype = $a->tolerancetype;
		$r_o->correctanswerlength = $a->correctanswerlength;
		$r_o->correctanswerformat = $a->correctanswerformat;
		$r_o->question = $r_qst->id;
		$r_o->answer = $r_an->id;
		$r_o->id = $DB->insert_record("question_calculated", $r_o);
	}
	foreach ($r_uts as $r_u) {
		$r_ut = new stdClass();
		$r_ut->unit = $r_u->name;
		$r_ut->multiplier = $r_u->multiplier;
		$r_ut->question = $r_qst->id;
		$r_ut->id = $DB->insert_record("question_numerical_units", $r_ut);
	}
	$r_o = new stdClass();
    $r_o->question = $r_qst->id;
    $r_o->unitpenalty = 0.1;
    if (count($r_uts) > 0) {
		$r_o->unitgradingtype = RWSGRD;
        $r_o->showunits = RWSUIN;
	}
    else {
		$r_o->unitgradingtype = RWSOPT;
        $r_o->showunits = RWSUNO;
	}
    $r_o->unitsleft = 0;
	if (RWSFCmp($CFG->version, 2011070100, 2) < 0) { 
		$r_o->instructions = "";
		$r_o->instructionsformat = FORMAT_HTML;
	}
	$r_o->id = $DB->insert_record("question_numerical_options", $r_o);
	foreach ($r_dset as $r_ds) {
		$r_df = new stdClass();
		$r_df->name = $r_ds->name;
		$r_df->options =
		  "$r_ds->distribution:$r_ds->min:$r_ds->max:$r_ds->precision";
		$r_df->itemcount = $r_ds->itemcount;
		$r_df->type = $r_ds->type;
		if ($r_ds->status == 0)
			$r_df->category = 0; 
		else 
			$r_df->category = $r_qst->category;
		$r_df->id = $DB->insert_record("question_dataset_definitions", $r_df);
		$r_qds = new stdClass();
		$r_qds->question = $r_qst->id;
		$r_qds->datasetdefinition = $r_df->id;
		$r_qds->id = $DB->insert_record("question_datasets", $r_qds);
		foreach ($r_ds->items as $r_di) {
			$r_it = new stdClass();
			$r_it->itemnumber = $r_di->itemnumber;
			$r_it->value = $r_di->value;
			$r_it->definition = $r_df->id;
			$r_it->id = $DB->insert_record("question_dataset_items", $r_it);
		}
	}
	return $r_qst->id;
}
function RWSCFSyn($r_for)
{
    while (ereg('\\{[[:alpha:]][^>} <{"\']*\\}', $r_for, $r_rgs)) {
        $r_for = str_replace($r_rgs[0], '1', $r_for);
    }
    $r_for = strtolower(str_replace(' ', '', $r_for));
	$r_soc = '-+/*%>:^~<?=&|!';
	$r_oon = "[$r_soc.0-9eE]";
    while (ereg("(^|[$r_soc,(])([a-z0-9_]*)\\(($r_oon+(,$r_oon+((,$r_oon+)+)?)?)?\\)",
            $r_for, $r_rgs)) {
		switch ($r_rgs[2]) {
            case '':
                if ((isset($r_rgs[4]) && $r_rgs[4]) || strlen($r_rgs[3])==0) {
                    return FALSE; 
                }
                break;
            case 'pi':
                if ($r_rgs[3]) {
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
                if (!empty($r_rgs[4]) || empty($r_rgs[3])) {
                    return FALSE; 
                }
                break;
            case 'log': case 'round':
                if (!empty($r_rgs[5]) || empty($r_rgs[3])) {
                    return FALSE; 
                }
                break;
            case 'atan2': case 'fmod': case 'pow':
                if (!empty($r_rgs[5]) || empty($r_rgs[4])) {
                    return FALSE; 
                }
                break;
            case 'min': case 'max':
                if (empty($r_rgs[4])) {
                    return FALSE; 
                }
                break;
            default:
                return FALSE; 
        }
        if ($r_rgs[1]) {
            $r_for = str_replace($r_rgs[0], $r_rgs[1] . '1', $r_for);
        } else {
            $r_for = ereg_replace("^$r_rgs[2]\\([^)]*\\)", '1', $r_for);
        }
    }
	if (ereg("[^$r_soc.0-9eE]+", $r_for, $r_rgs)) {
		return FALSE; 
    } else {
        return TRUE; 
    }
}
function RWSIMCRec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWSPFNAME;
	if (RWSGQRType($r_rcd) != RWSMCH)
		return FALSE;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSMCH;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = $r_dat[1];
	else
		$r_qst->defaultgrade = $r_dat[1];
	$r_ct = 8;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->penalty = RWSDblIn($r_fld);
	if ($r_qst->penalty < 0 || $r_qst->penalty > 1)
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($r_qst->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$r_qst->penalty = "0.3333333";
			break;
		}
	}
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_op = new stdClass();
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_op->single = intval($r_dat[1]);
	if ($r_op->single != 0 && $r_op->single != 1)
		return FALSE;
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_flg = intval($r_dat[1]);
	if ($r_flg != 0 && $r_flg != 1)
		return FALSE;
	$r_op->shuffleanswers = (bool)$r_flg;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_op->answernumbering = trim($r_fld); 
	switch ($r_op->answernumbering) {
	case "abc":
	case "ABCD":
	case "123":
	case "none":
		break;
	default:
		return FALSE;
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_na = intval($r_dat[1]);
	if ($r_na < 2)
		return FALSE;
	$r_asrs = array();
	$r_tf = 0;
	$r_mf = -1;
	for ($r_i = 0; $r_i < $r_na; $r_i++) {
		$r_asr = new stdClass();
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_asr->answer = trim($r_fld); 
		$r_asr->answerformat = FORMAT_HTML;
		$r_asr->answer = clean_param($r_asr->answer, PARAM_RAW);
		$r_ct = 8;
		if ($r_sz < $r_ct)
			return FALSE;
		$r_fld = substr($r_rcd, $r_p, $r_ct);
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_asr->fraction = strval(RWSDblIn($r_fld));
		switch ($r_asr->fraction) {
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
				if (RWSFCmp($r_bv, 2011020100, 2) >= 0)
					$r_asr->fraction = "0";
				break;
		}
		if (RWSFCmp($r_bv, 2011020100, 2) == -1) {
			switch ($r_asr->fraction) { 
				case "0.83333":
					$r_asr->fraction = "0.8333333";
					break;
				case "0.66666":
					$r_asr->fraction = "0.6666667";
					break;
				case "0.33333":
					$r_asr->fraction = "0.3333333";
					break;
				case "0.16666":
					$r_asr->fraction = "0.1666667";
					break;
				case "0.142857":
					$r_asr->fraction = "0.1428571";
					break;
				case "0.11111":
					$r_asr->fraction = "0.1111111";
					break;
				case "-0.11111":
					$r_asr->fraction = "-0.1111111";
					break;
				case "-0.142857":
					$r_asr->fraction = "-0.1428571";
					break;
				case "-0.16666":
					$r_asr->fraction = "-0.1666667";
					break;
				case "-0.33333":
					$r_asr->fraction = "-0.3333333";
					break;
				case "-0.66666":
					$r_asr->fraction = "-0.6666667";
					break;
				case "-0.83333":
					$r_asr->fraction = "-0.8333333";
					break;
				default:
					$r_asr->fraction = "0";
					break;
			}
		}
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_asr->feedback = trim($r_fld); 
		$r_asr->feedbackformat = FORMAT_HTML;
		$r_asr->feedback = clean_param($r_asr->feedback, PARAM_RAW);
		if (strlen($r_asr->answer) == 0)
			continue;
		$r_asrs[] = $r_asr;
		if ($r_asr->fraction > 0)
			$r_tf += $r_asr->fraction;
		if ($r_asr->fraction > $r_mf)
			$r_mf = $r_asr->fraction;
	}
	if (count($r_asrs) < 2)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_op->correctfeedback = trim($r_fld); 
	$r_op->correctfeedbackformat = FORMAT_HTML;
	$r_op->correctfeedback = clean_param($r_op->correctfeedback, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_op->partiallycorrectfeedback = trim($r_fld); 
	if (strlen($RWSPFNAME) > 0)
		$r_op->$RWSPFNAME = FORMAT_HTML;
	$r_op->partiallycorrectfeedback = clean_param($r_op->partiallycorrectfeedback, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_op->incorrectfeedback = trim($r_fld); 
	$r_op->incorrectfeedbackformat = FORMAT_HTML;
	$r_op->incorrectfeedback = clean_param($r_op->incorrectfeedback, PARAM_RAW);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_op->shownumcorrect = 0;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	$r_aid = array();
	foreach ($r_asrs as $r_an) {
		$r_an->question = $r_qst->id;
		$r_an->id = $DB->insert_record("question_answers", $r_an);
		$r_cmp = "question";
		$r_far = "answer";
		$r_iti = $r_an->id;
		$r_txt = $r_an->answer;
		$r_an->answer = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_an->id;
		$r_txt = $r_an->feedback;
		$r_an->feedback = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question_answers", $r_an);
		$r_aid[] = $r_an->id;
	}
	$r_op->question = $r_qst->id;
	$r_op->answers = implode(",", $r_aid);
	$r_op->id = $DB->insert_record("question_multichoice", $r_op);
	$r_cmp = "qtype_multichoice";
	$r_far = "correctfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_op->correctfeedback;
	$r_op->correctfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "qtype_multichoice";
	$r_far = "partiallycorrectfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_op->partiallycorrectfeedback;
	$r_op->partiallycorrectfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "qtype_multichoice";
	$r_far = "incorrectfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_op->incorrectfeedback;
	$r_op->incorrectfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question_multichoice", $r_op);
	return $r_qst->id;
}
function RWSIMRec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	global $RWSPFNAME;
	if (RWSGQRType($r_rcd) != RWSMAT)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSMAT;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = $r_dat[1];
	else
		$r_qst->defaultgrade = $r_dat[1];
	$r_ct = 8;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->penalty = RWSDblIn($r_fld);
	if ($r_qst->penalty < 0 || $r_qst->penalty > 1)
		return FALSE;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		switch (strval($r_qst->penalty)) {
		case "1":
		case "0.5":
		case "0.3333333":
		case "0.25":
		case "0.2":
		case "0.1":
		case "0":
			break;
		default:
			$r_qst->penalty = "0.3333333";
			break;
		}
	}
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_op = new stdClass();
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_flg = intval($r_dat[1]);
	if ($r_flg != 0 && $r_flg != 1)
		return FALSE;
	$r_op->shuffleanswers = (bool)$r_flg;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_op->correctfeedback = "";
		$r_op->correctfeedbackformat = FORMAT_HTML;
		$r_op->partiallycorrectfeedback = "";
		if (strlen($RWSPFNAME) > 0)
			$r_op->$RWSPFNAME = FORMAT_HTML;
		$r_op->incorrectfeedback = "";
		$r_op->incorrectfeedbackformat = FORMAT_HTML;
		$r_op->shownumcorrect = 0;
	}
	$r_ct = 1;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("C", $r_fld);
	$r_np = intval($r_dat[1]);
	if ($r_np < 3)
		return FALSE;
	$r_prs = array();
	$r_sbqct = 0;
	for ($r_i = 0; $r_i < $r_np; $r_i++) {
		$r_sbq = new stdClass();
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_sbq->questiontext = trim($r_fld); 
		$r_sbq->questiontextformat = FORMAT_HTML;
		$r_sbq->questiontext = clean_param($r_sbq->questiontext, PARAM_RAW);
		if ($r_sz < 1)
			return FALSE;
		$r_ct = strpos(substr($r_rcd, $r_p), "\0");
		if ($r_ct === FALSE)
			return FALSE;
		if ($r_ct > 0)
			$r_fld = substr($r_rcd, $r_p, $r_ct);
		else
			$r_fld = "";
		$r_ct++; 
		$r_p += $r_ct;
		$r_sz -= $r_ct;
		$r_sbq->answertext = trim($r_fld); 
		$r_sbq->answertext = clean_param($r_sbq->answertext, PARAM_TEXT);
		if (strlen($r_sbq->answertext) == 0)
			continue;
		if (strlen($r_sbq->questiontext) != 0)
			$r_sbqct++;
		$r_prs[] = $r_sbq;
	}
	if ($r_sbqct < 2 || count($r_prs) < 3)
		return FALSE;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	$r_pis = array();
	foreach ($r_prs as $r_pr) {
        $r_pr->code = rand(1, 999999999);
        while ($DB->record_exists("question_match_sub", array(
		  "code" => $r_pr->code, "question" => $r_qst->id
		  )) === TRUE) {
            $r_pr->code = rand(1, 999999999);
        }
		$r_pr->question = $r_qst->id;
		$r_pr->id = $DB->insert_record("question_match_sub", $r_pr);
		$r_cmp = "qtype_match";
		$r_far = "subquestion";
		$r_iti = $r_pr->id;
		$r_txt = $r_pr->questiontext;
		$r_pr->questiontext = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("question_match_sub", $r_pr);
		$r_pis[] = $r_pr->id;
	}
	$r_op->question = $r_qst->id;
	$r_op->subquestions = implode(",", $r_pis);
	$r_op->id = $DB->insert_record("question_match", $r_op);
	return $r_qst->id;
}
function RWSIDRec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGQRType($r_rcd) != RWSDES)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSDES;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 0;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = 0;
	else
		$r_qst->defaultgrade = 0;
	$r_qst->penalty = 0;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	return $r_qst->id;
}
function RWSIERec($r_cid, $r_qci, $r_rcd)
{
	global $CFG;
	global $DB;
	global $USER;
	if (RWSGQRType($r_rcd) != RWSESS)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qci));
	$r_qst = new stdClass();
	$r_qst->qtype = RWSESS;
	$r_qst->parent = 0;
	$r_qst->hidden = 0;
	$r_qst->length = 1;
	$r_qst->category = $r_qci;
	$r_qst->stamp = make_unique_id_code();
	$r_qst->createdby = $USER->id;
	$r_qst->modifiedby = $USER->id;
	$r_qst->penalty = 0;
	$r_p = 1;
	$r_ct = 4;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_sz = $r_dat[1];
	if (strlen($r_rcd) != $r_p + $r_sz)
		return FALSE;
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE || $r_ct < 1)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->name = trim($r_fld); 
	if (strlen($r_qst->name) == 0)
		return FALSE;
	$r_qst->name = clean_param($r_qst->name, PARAM_TEXT);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->questiontext = trim($r_fld); 
	$r_qst->questiontextformat = FORMAT_HTML;
	$r_qst->questiontext = clean_param($r_qst->questiontext, PARAM_RAW);
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_qst->defaultmark = $r_dat[1];
	else
		$r_qst->defaultgrade = $r_dat[1];
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->generalfeedback = trim($r_fld); 
	$r_qst->generalfeedbackformat = FORMAT_HTML;
	$r_qst->generalfeedback = clean_param($r_qst->generalfeedback, PARAM_RAW);
	$r_asr = new stdClass();
	$r_asr->fraction = 0; 
	if ($r_sz < 1)
		return FALSE;
	$r_ct = strpos(substr($r_rcd, $r_p), "\0");
	if ($r_ct === FALSE)
		return FALSE;
	if ($r_ct > 0)
		$r_fld = substr($r_rcd, $r_p, $r_ct);
	else
		$r_fld = "";
	$r_ct++; 
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_asr->feedback = trim($r_fld); 
	$r_asr->feedbackformat = FORMAT_HTML;
	$r_asr->feedback = clean_param($r_asr->feedback, PARAM_RAW);
	$r_asr->answer = $r_asr->feedback;
	$r_asr->answerformat = $r_asr->feedbackformat;
	$r_ct = 4;
	if ($r_sz < $r_ct)
		return FALSE;
	$r_fld = substr($r_rcd, $r_p, $r_ct);
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_dat = unpack("N", $r_fld);
	$r_ct = $r_dat[1];
	if ($r_sz < $r_ct)
		return FALSE;
	$r_p += $r_ct;
	$r_sz -= $r_ct;
	$r_qst->timecreated = time();
	$r_qst->timemodified = time();
	$r_qst->id = $DB->insert_record("question", $r_qst);
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->questiontext;
	$r_qst->questiontext = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_txt = $r_qst->generalfeedback;
	$r_qst->generalfeedback = RWSPAtt($r_qst->qtype,
	  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
	  );
	$DB->update_record("question", $r_qst);
	$r_h = question_hash($r_qst);
	$DB->set_field("question", "version", $r_h, array("id" => $r_qst->id));
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_op = new stdClass();
		$r_op->questionid = $r_qst->id;
		$r_op->responseformat = "editor"; 
		$r_op->responsefieldlines = 15; 
		$r_op->attachments = 0; 
		$r_op->graderinfo = $r_asr->answer;
		$r_op->graderinfoformat = $r_asr->answerformat;
		$r_op->id = $DB->insert_record("qtype_essay_options", $r_op);
		$r_cmp = "qtype_essay";
		$r_far = "graderinfo";
		$r_iti = $r_qst->id;
		$r_txt = $r_op->graderinfo;
		$r_op->graderinfo = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$DB->update_record("qtype_essay_options", $r_op);
	}
	else { 
		$r_asr->question = $r_qst->id;
		$r_asr->id = $DB->insert_record("question_answers", $r_asr);
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_asr->id;
		$r_txt = $r_asr->feedback;
		$r_asr->feedback = RWSPAtt($r_qst->qtype,
		  $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt
		  );
		$r_asr->answer = $r_asr->feedback;
		$DB->update_record("question_answers", $r_asr);
	}
	return $r_qst->id;
}
function RWSESRec($r_qiz)
{
	global $DB;
	global $RWSLB;
	global $CFG;
	$r_ctx = get_context_instance(CONTEXT_MODULE, $r_qiz->coursemodule);
	$r_ctxi = $r_ctx->id;
	$r_txt = $r_qiz->intro;
	$r_scr = "pluginfile.php";
	$r_cmp = "mod_quiz";
	$r_far = "intro";
	$r_iti = 0;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	if ($r_qiz->timeopen == 0) {
		$r_y = 0;
		$r_mo = 0;
		$r_da = 0;
		$r_hr = 0;
		$r_mt = 0;
	}
	else {
		$r_std = usergetdate($r_qiz->timeopen);
		$r_y = $r_std['year'];
		$r_mo = $r_std['mon'];
		$r_da = $r_std['mday'];
		$r_hr = $r_std['hours'];
		$r_mt = $r_std['minutes'];
	}
	$r_fld = pack("nC*", $r_y, $r_mo, $r_da, $r_hr, $r_mt);
	$r_rcd .= $r_fld;
	if ($r_qiz->timeclose == 0) {
		$r_y = 0;
		$r_mo = 0;
		$r_da = 0;
		$r_hr = 0;
		$r_mt = 0;
	}
	else {
		$r_edt = usergetdate($r_qiz->timeclose);
		$r_y = $r_edt['year'];
		$r_mo = $r_edt['mon'];
		$r_da = $r_edt['mday'];
		$r_hr = $r_edt['hours'];
		$r_mt = $r_edt['minutes'];
	}
	$r_fld = pack("nC*", $r_y, $r_mo, $r_da, $r_hr, $r_mt);
	$r_rcd .= $r_fld;
	$r_en = ($r_qiz->timelimit == 0) ? 0 : 1;
	$r_mts = $r_qiz->timelimit / 60;
	if ($r_mts * 60 < $r_qiz->timelimit)
		$r_mts += 1;
	$r_fld = pack("CN", $r_en, $r_mts);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->delay1;
	if ($r_fld < 900)
		$r_fld = 0; 
	else if ($r_fld < 2700)
		$r_fld = 1800; 
	else if ($r_fld < 5400)
		$r_fld = 3600; 
	else if ($r_fld < 9000)
		$r_fld = 7200; 
	else if ($r_fld < 12600)
		$r_fld = 10800; 
	else if ($r_fld < 16200)
		$r_fld = 14400; 
	else if ($r_fld < 19800)
		$r_fld = 18000; 
	else if ($r_fld < 23400)
		$r_fld = 21600; 
	else if ($r_fld < 27000)
		$r_fld = 25200; 
	else if ($r_fld < 30600)
		$r_fld = 28800; 
	else if ($r_fld < 34200)
		$r_fld = 32400; 
	else if ($r_fld < 37800)
		$r_fld = 36000; 
	else if ($r_fld < 41400)
		$r_fld = 39600; 
	else if ($r_fld < 45000)
		$r_fld = 43200; 
	else if ($r_fld < 48600)
		$r_fld = 46800; 
	else if ($r_fld < 52200)
		$r_fld = 50400; 
	else if ($r_fld < 55800)
		$r_fld = 54000; 
	else if ($r_fld < 59400)
		$r_fld = 57600; 
	else if ($r_fld < 63000)
		$r_fld = 61200; 
	else if ($r_fld < 66600)
		$r_fld = 64800; 
	else if ($r_fld < 70200)
		$r_fld = 68400; 
	else if ($r_fld < 73800)
		$r_fld = 72000; 
	else if ($r_fld < 77400)
		$r_fld = 75600; 
	else if ($r_fld < 81000)
		$r_fld = 79200; 
	else if ($r_fld < 84600)
		$r_fld = 82800; 
	else if ($r_fld < 126000)
		$r_fld = 86400; 
	else if ($r_fld < 216000)
		$r_fld = 172800; 
	else if ($r_fld < 302400)
		$r_fld = 259200; 
	else if ($r_fld < 388800)
		$r_fld = 345600; 
	else if ($r_fld < 475200)
		$r_fld = 432000; 
	else if ($r_fld < 561600)
		$r_fld = 518400; 
	else
		$r_fld = 604800; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->delay2;
	if ($r_fld < 900)
		$r_fld = 0; 
	else if ($r_fld < 2700)
		$r_fld = 1800; 
	else if ($r_fld < 5400)
		$r_fld = 3600; 
	else if ($r_fld < 9000)
		$r_fld = 7200; 
	else if ($r_fld < 12600)
		$r_fld = 10800; 
	else if ($r_fld < 16200)
		$r_fld = 14400; 
	else if ($r_fld < 19800)
		$r_fld = 18000; 
	else if ($r_fld < 23400)
		$r_fld = 21600; 
	else if ($r_fld < 27000)
		$r_fld = 25200; 
	else if ($r_fld < 30600)
		$r_fld = 28800; 
	else if ($r_fld < 34200)
		$r_fld = 32400; 
	else if ($r_fld < 37800)
		$r_fld = 36000; 
	else if ($r_fld < 41400)
		$r_fld = 39600; 
	else if ($r_fld < 45000)
		$r_fld = 43200; 
	else if ($r_fld < 48600)
		$r_fld = 46800; 
	else if ($r_fld < 52200)
		$r_fld = 50400; 
	else if ($r_fld < 55800)
		$r_fld = 54000; 
	else if ($r_fld < 59400)
		$r_fld = 57600; 
	else if ($r_fld < 63000)
		$r_fld = 61200; 
	else if ($r_fld < 66600)
		$r_fld = 64800; 
	else if ($r_fld < 70200)
		$r_fld = 68400; 
	else if ($r_fld < 73800)
		$r_fld = 72000; 
	else if ($r_fld < 77400)
		$r_fld = 75600; 
	else if ($r_fld < 81000)
		$r_fld = 79200; 
	else if ($r_fld < 84600)
		$r_fld = 82800; 
	else if ($r_fld < 126000)
		$r_fld = 86400; 
	else if ($r_fld < 216000)
		$r_fld = 172800; 
	else if ($r_fld < 302400)
		$r_fld = 259200; 
	else if ($r_fld < 388800)
		$r_fld = 345600; 
	else if ($r_fld < 475200)
		$r_fld = 432000; 
	else if ($r_fld < 561600)
		$r_fld = 518400; 
	else
		$r_fld = 604800; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->questionsperpage;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->shufflequestions;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->shuffleanswers;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->attempts;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->attemptonlast;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		if ($r_qiz->preferredbehaviour == "adaptive"
		  || $r_qiz->preferredbehaviour == "adaptivenopenalty")
			$r_fld = 1;
		else
			$r_fld = 0;
	}
	else { 
		$r_fld = $r_qiz->optionflags & RWSQAD;
	}
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->grade;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->grademethod;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		if ($r_qiz->preferredbehaviour == "adaptive")
			$r_fld = 1;
		else
			$r_fld = 0;
	}
	else { 
		$r_fld = $r_qiz->penaltyscheme;
	}
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->decimalpoints;
	if ($r_fld > 3)
		$r_fld = 3;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_rsps = (($r_qiz->reviewattempt & RWSRDU)
		  || ($r_qiz->reviewattempt & RWSRIA)) ? 1 : 0;
		$r_asrs = (($r_qiz->reviewrightanswer & RWSRDU)
		  || ($r_qiz->reviewrightanswer & RWSRIA)) ? 1 : 0;
		$r_fb = (($r_qiz->reviewspecificfeedback & RWSRDU)
		  || ($r_qiz->reviewspecificfeedback & RWSRIA)) ? 1 : 0;
		$r_gen = (($r_qiz->reviewgeneralfeedback & RWSRDU)
		  || ($r_qiz->reviewgeneralfeedback & RWSRIA)) ? 1 : 0;
		$r_sc = (($r_qiz->reviewmarks & RWSRDU)
		  || ($r_qiz->reviewmarks & RWSRIA)
		  || ($r_qiz->reviewcorrectness & RWSRDU)
		  || ($r_qiz->reviewcorrectness & RWSRIA)) ? 1 : 0;
		$r_ov = (($r_qiz->reviewoverallfeedback & RWSRDU)
		  || ($r_qiz->reviewoverallfeedback & RWSRIA)) ? 1 : 0;
	}
	else { 
		$r_rsps = ($r_qiz->review & RWSRRE & RWSRIM) ? 1 : 0;
		$r_asrs = ($r_qiz->review & RWSRAN & RWSRIM) ? 1 : 0;
		$r_fb = ($r_qiz->review & RWSRFE & RWSRIM) ? 1 : 0;
		$r_gen = ($r_qiz->review & RWSRGE & RWSRIM) ? 1 : 0;
		$r_sc = ($r_qiz->review & RWSRSC & RWSRIM) ? 1 : 0;
		$r_ov = ($r_qiz->review & RWSROV & RWSRIM) ? 1 : 0;
	}
	$r_fld = pack("C*", $r_rsps, $r_asrs, $r_fb, $r_gen, $r_sc, $r_ov);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_rsps = ($r_qiz->reviewattempt & RWSRLA) ? 1 : 0;
		$r_asrs = ($r_qiz->reviewrightanswer & RWSRLA) ? 1 : 0;
		$r_fb = ($r_qiz->reviewspecificfeedback & RWSRLA) ? 1 : 0;
		$r_gen = ($r_qiz->reviewgeneralfeedback & RWSRLA) ? 1 : 0;
		$r_sc = (($r_qiz->reviewcorrectness & RWSRLA)
		  || ($r_qiz->reviewmarks & RWSRLA)) ? 1 : 0;
		$r_ov = ($r_qiz->reviewoverallfeedback & RWSRLA) ? 1 : 0;
	}
	else { 
		$r_rsps = ($r_qiz->review & RWSRRE & RWSROP) ? 1 : 0;
		$r_asrs = ($r_qiz->review & RWSRAN & RWSROP) ? 1 : 0;
		$r_fb = ($r_qiz->review & RWSRFE & RWSROP) ? 1 : 0;
		$r_gen = ($r_qiz->review & RWSRGE & RWSROP) ? 1 : 0;
		$r_sc = ($r_qiz->review & RWSRSC & RWSROP) ? 1 : 0;
		$r_ov = ($r_qiz->review & RWSROV & RWSROP) ? 1 : 0;
	}
	$r_fld = pack("C*", $r_rsps, $r_asrs, $r_fb, $r_gen, $r_sc, $r_ov);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_rsps = ($r_qiz->reviewattempt & RWSRAF) ? 1 : 0;
		$r_asrs = ($r_qiz->reviewrightanswer & RWSRAF) ? 1 : 0;
		$r_fb = ($r_qiz->reviewspecificfeedback & RWSRAF) ? 1 : 0;
		$r_gen = ($r_qiz->reviewgeneralfeedback & RWSRAF) ? 1 : 0;
		$r_sc = (($r_qiz->reviewcorrectness & RWSRAF)
		  || ($r_qiz->reviewmarks & RWSRAF)) ? 1 : 0;
		$r_ov = ($r_qiz->reviewoverallfeedback & RWSRAF) ? 1 : 0;
	}
	else { 
		$r_rsps = ($r_qiz->review & RWSRRE & RWSRCL) ? 1 : 0;
		$r_asrs = ($r_qiz->review & RWSRAN & RWSRCL) ? 1 : 0;
		$r_fb = ($r_qiz->review & RWSRFE & RWSRCL) ? 1 : 0;
		$r_gen = ($r_qiz->review & RWSRGE & RWSRCL) ? 1 : 0;
		$r_sc = ($r_qiz->review & RWSRSC & RWSRCL) ? 1 : 0;
		$r_ov = ($r_qiz->review & RWSROV & RWSRCL) ? 1 : 0;
	}
	$r_fld = pack("C*", $r_rsps, $r_asrs, $r_fb, $r_gen, $r_sc, $r_ov);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->popup;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->password;
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->subnet;
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->groupmode;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->visible;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qiz->cmidnumber;
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "1"; 
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fbt = array();
	$r_fbb = array();
	$r_qzf = $DB->get_records("quiz_feedback",
	  array("quizid" => $r_qiz->id), "mingrade DESC");
	if (count($r_qzf) > 0) {
		foreach ($r_qzf as $r_qf) {
			$r_txt = $r_qf->feedbacktext;
			$r_scr = "pluginfile.php";
			$r_cmp = "mod_quiz";
			$r_far = "feedback";
			$r_iti = $r_qf->id;
			$r_fbt[] = file_rewrite_pluginfile_urls(
			  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
			  );
            if ($r_qf->mingrade > 0) {
				$r_bd = (100.0 * $r_qf->mingrade / $r_qiz->grade) . "%";
				$r_fbb[] = $r_bd;
			}
		}
	}
	$r_fld = count($r_fbt);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	if (count($r_fbt) > 0) {
		foreach($r_fbt as $r_fd) {
			$r_fld = $r_fd;
			if (!RWSIVUtf8($r_fld))
				$r_fld = utf8_encode($r_fld);
			$r_fld = pack("a*x", $r_fld);
			$r_rcd .= $r_fld;
		}
	}
	$r_fld = count($r_fbb);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	foreach($r_fbb as $r_bd) {
		$r_fld = $r_bd;
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
	}
	RWSLLBSet($r_qiz);
	$r_fld = $RWSLB->atts;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $RWSLB->revs;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $RWSLB->pw;
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	return $r_rcd;
}
function RWSLLBSet($r_qiz)
{
	global $RWSLB;
	$RWSLB->atts = 0; 
	$RWSLB->revs = 0; 
	$RWSLB->pw = ""; 
	$RWSLB->gerr = FALSE;
	if ($RWSLB->mok) {
		$r_op = lockdown_get_quiz_options($r_qiz->instance);
		if (!$r_op)
			$RWSLB->gerr = TRUE;
		else {
			$RWSLB->atts = $r_op->attempts;
			$RWSLB->revs = $r_op->reviews;
			$RWSLB->pw = $r_op->password;
		}
	} else if ($RWSLB->bok) {
		$r_op = lockdown_get_quiz_options($r_qiz->instance);
		if (!$r_op)
			$RWSLB->gerr = TRUE;
		else {
			$RWSLB->atts = $r_op->attempts;
		}
	}
}
function RWSERRec($r_dat)
{
	$r_rcd = "";
	$r_l = strlen($r_dat);
	if ($r_l > 0)
		$r_rcd .= $r_dat;
	if ($r_l > 0) {
		$r_fld = crc32($r_dat);
		$r_fld = pack("N", $r_fld);
		$r_rcd .= $r_fld;
	}
	$r_rd  = pack("C", 12); 
	$r_rd .= pack("N", strlen($r_rcd)); 
	$r_rd .= $r_rcd; 
	return $r_rd;
}
function RWSESARec($r_qst)
{
	global $DB;
	global $CFG;
	if ($r_qst->qtype != RWSSHA)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_fld = $r_qst->defaultmark;
	else
		$r_fld = $r_qst->defaultgrade;
	if ($r_fld < 0)
		$r_fld = 0;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qst->penalty;
	$r_fld = RWSDblOut($r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_op = $DB->get_record("question_shortanswer",
	  array("question" => $r_qst->id));
	if ($r_op === FALSE)
		return FALSE;
	$r_fld = $r_op->usecase;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_asrs = array();
	$r_aid = explode(",", $r_op->answers);
	foreach($r_aid as $r_id) {
		$r_asr = $DB->get_record("question_answers", array("id" => $r_id));
		if ($r_asr === FALSE)
			return FALSE;
		$r_asrs[] = $r_asr;
	}
	$r_fld = count($r_asrs);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	foreach($r_asrs as $r_asr) {
		$r_fld = $r_asr->answer;
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_asr->fraction;
		if (RWSFCmp($r_bv, 2011020100, 2) == -1) {
			switch (strval($r_fld)) {
			case "0.8333333":
				$r_fld = "0.83333";
				break;
			case "0.6666667":
				$r_fld = "0.66666";
				break;
			case "0.3333333":
				$r_fld = "0.33333";
				break;
			case "0.1666667":
				$r_fld = "0.16666";
				break;
			case "0.1428571":
				$r_fld = "0.142857";
				break;
			case "0.1111111":
				$r_fld = "0.11111";
				break;
			default:
				break;
			}
		}
		$r_fld = RWSDblOut($r_fld);
		$r_rcd .= $r_fld;
		$r_txt = $r_asr->feedback;
		$r_scr = "pluginfile.php";
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_asr->id;
		$r_fld = file_rewrite_pluginfile_urls(
		  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
		  );
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
	}
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 3); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSETFRec($r_qst)
{
	global $DB;
	global $CFG;
	if ($r_qst->qtype != RWSTRF)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_fld = $r_qst->defaultmark;
	else
		$r_fld = $r_qst->defaultgrade;
	if ($r_fld < 0)
		$r_fld = 0;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qst->penalty;
	$r_fld = RWSDblOut($r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_op = $DB->get_record("question_truefalse",
	  array("question" => $r_qst->id));
	if ($r_op === FALSE)
		return FALSE;
	$r_tru = $DB->get_record("question_answers",
	  array("id" => $r_op->trueanswer));
	if ($r_tru === FALSE)
		return FALSE;
	$r_fal = $DB->get_record("question_answers",
	  array("id" => $r_op->falseanswer));
	if ($r_fal === FALSE)
		return FALSE;
	$r_fld = $r_tru->fraction;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_tru->feedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "answerfeedback";
	$r_iti = $r_tru->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_fal->feedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "answerfeedback";
	$r_iti = $r_fal->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 2); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSEMARec($r_qst)
{
	global $DB;
	if ($r_qst->qtype != RWSMAN)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_qst->questiontext = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	$r_clzf = RWSGCFields($r_qst->questiontext);
	if ($r_clzf === FALSE)
		return FALSE;
	$r_op = $DB->get_record("question_multianswer",
	  array("question" => $r_qst->id));
	if ($r_op === FALSE)
		return FALSE;
	$r_chid = explode(",", $r_op->sequence);
	$r_chc = count($r_chid);
	if ($r_chc != count($r_clzf))
		return FALSE;
	for ($r_i = 0; $r_i < $r_chc; $r_i++) {
		$r_chd = $DB->get_record("question", array("id" => $r_chid[$r_i]));
		if ($r_chd === FALSE)
			return FALSE;
		$r_txt = $r_chd->questiontext;
		$r_scr = "pluginfile.php";
		$r_cmp = "question";
		$r_far = "questiontext";
		$r_iti = $r_chd->id;
		$r_chd->questiontext = file_rewrite_pluginfile_urls(
		  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
		  );
		$r_qst->questiontext = implode($r_chd->questiontext,
		  explode($r_clzf[$r_i], $r_qst->questiontext, 2));
	}
	$r_fld = $r_qst->questiontext;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qst->penalty;
	$r_fld = RWSDblOut($r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 9); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSCRFISort($r_rc1, $r_rc2)
{
	if ($r_rc1->id == $r_rc2->id)
		return 0;
	return ($r_rc1->id < $r_rc2->id) ? -1 : 1;
}
function RWSECRec($r_qst)
{
	global $DB;
	global $CFG;
	if ($r_qst->qtype != RWSCAL
	  && $r_qst->qtype != RWSCSI)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_fld = $r_qst->defaultmark;
	else
		$r_fld = $r_qst->defaultgrade;
	if ($r_fld < 0)
		$r_fld = 0;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qst->penalty;
	$r_fld = RWSDblOut($r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_asrs = $DB->get_records("question_answers",
	  array("question" => $r_qst->id));
	if (count($r_asrs) == 0)
		return FALSE;
	if (count($r_asrs) > 1)
		usort($r_asrs, "RWSCRFISort");
	$r_fld = count($r_asrs);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	foreach($r_asrs as $r_an) {
		$r_fld = $r_an->answer;
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_an->fraction;
		if (RWSFCmp($r_bv, 2011020100, 2) == -1) {
			switch (strval($r_fld)) {
			case "0.8333333":
				$r_fld = "0.83333";
				break;
			case "0.6666667":
				$r_fld = "0.66666";
				break;
			case "0.3333333":
				$r_fld = "0.33333";
				break;
			case "0.1666667":
				$r_fld = "0.16666";
				break;
			case "0.1428571":
				$r_fld = "0.142857";
				break;
			case "0.1111111":
				$r_fld = "0.11111";
				break;
			default:
				break;
			}
		}
		$r_fld = RWSDblOut($r_fld);
		$r_rcd .= $r_fld;
		$r_txt = $r_an->feedback;
		$r_scr = "pluginfile.php";
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_an->id;
		$r_fld = file_rewrite_pluginfile_urls(
		  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
		  );
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		$r_o = $DB->get_record("question_calculated",
		  array("answer" => $r_an->id));
		if ($r_o === FALSE)
			return FALSE;
		$r_fld = $r_o->tolerance;
		$r_fld = RWSDblOut($r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_o->tolerancetype;
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_o->correctanswerlength;
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_o->correctanswerformat;
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
	}
	$r_uts = $DB->get_records("question_numerical_units",
	  array("question" => $r_qst->id));
	if (count($r_uts) > 1)
		usort($r_uts, "RWSCRFISort");
	$r_fld = count($r_uts);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	if (count($r_uts) > 0) {
		foreach($r_uts as $r_ut) {
			$r_fld = $r_ut->unit;
			$r_fld = pack("a*x", $r_fld);
			$r_rcd .= $r_fld;
			$r_fld = $r_ut->multiplier;
			$r_fld = RWSDblOut($r_fld);
			$r_rcd .= $r_fld;
		}
	}
	$r_dset = $DB->get_records("question_datasets",
	  array("question" => $r_qst->id));
	if (count($r_dset) == 0)
		return FALSE;
	$r_fld = count($r_dset);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	foreach($r_dset as $r_qds) {
		$r_df = $DB->get_record("question_dataset_definitions",
		  array("id" => $r_qds->datasetdefinition));
		if ($r_df === FALSE)
			return FALSE;
		$r_fld = $r_df->name;
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		list($r_dstr, $r_mi, $r_mx, $r_pre) =
		  explode(":", $r_df->options, 4);
		$r_fld = $r_dstr;
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_mi;
		$r_fld = RWSDblOut($r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_mx;
		$r_fld = RWSDblOut($r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_pre;
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_df->type;
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
		if ($r_df->category == 0)
			$r_fld = 0; 
		else 
			$r_fld = 1;
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
		$r_its = $DB->get_records("question_dataset_items",
		  array("definition" => $r_df->id));
		if (count($r_its) == 0)
			return FALSE;
		$r_fld = count($r_its);
		$r_fld = pack("C", $r_fld);
		$r_rcd .= $r_fld;
		foreach($r_its as $r_it) {
			$r_fld = $r_it->itemnumber;
			$r_fld = pack("C", $r_fld);
			$r_rcd .= $r_fld;
			$r_fld = $r_it->value;
			$r_fld = RWSDblOut($r_fld);
			$r_rcd .= $r_fld;
		}
	}
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 7); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSEMCRec($r_qst)
{
	global $DB;
	global $CFG;
	if ($r_qst->qtype != RWSMCH)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_fld = $r_qst->defaultmark;
	else
		$r_fld = $r_qst->defaultgrade;
	if ($r_fld < 0)
		$r_fld = 0;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qst->penalty;
	$r_fld = RWSDblOut($r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_op = $DB->get_record("question_multichoice",
	  array("question" => $r_qst->id));
	if ($r_op === FALSE)
		return FALSE;
	$r_fld = $r_op->single;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_op->shuffleanswers;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_op->answernumbering;
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_asrs = array();
	$r_aid = explode(",", $r_op->answers);
	foreach($r_aid as $r_id) {
		$r_asr = $DB->get_record("question_answers", array("id" => $r_id));
		if ($r_asr === FALSE)
			return FALSE;
		$r_asrs[] = $r_asr;
	}
	$r_fld = count($r_asrs);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	foreach($r_asrs as $r_asr) {
		$r_txt = $r_asr->answer;
		$r_scr = "pluginfile.php";
		$r_cmp = "question";
		$r_far = "answer";
		$r_iti = $r_asr->id;
		$r_fld = file_rewrite_pluginfile_urls(
		  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
		  );
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_asr->fraction;
		if (RWSFCmp($r_bv, 2011020100, 2) == -1) {
			switch (strval($r_fld)) {
			case "0.8333333":
				$r_fld = "0.83333";
				break;
			case "0.6666667":
				$r_fld = "0.66666";
				break;
			case "0.3333333":
				$r_fld = "0.33333";
				break;
			case "0.1666667":
				$r_fld = "0.16666";
				break;
			case "0.1428571":
				$r_fld = "0.142857";
				break;
			case "0.1111111":
				$r_fld = "0.11111";
				break;
			case "-0.1111111":
				$r_fld = "-0.11111";
				break;
			case "0.1428571":
				$r_fld = "-0.142857";
				break;
			case "0.1666667":
				$r_fld = "-0.16666";
				break;
			case "0.3333333":
				$r_fld = "-0.33333";
				break;
			case "0.6666667":
				$r_fld = "-0.66666";
				break;
			case "0.8333333":
				$r_fld = "-0.83333";
				break;
			default:
				break;
			}
		}
		$r_fld = RWSDblOut($r_fld);
		$r_rcd .= $r_fld;
		$r_txt = $r_asr->feedback;
		$r_scr = "pluginfile.php";
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_asr->id;
		$r_fld = file_rewrite_pluginfile_urls(
		  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
		  );
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
	}
	$r_txt = $r_op->correctfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "qtype_multichoice";
	$r_far = "correctfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_op->partiallycorrectfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "qtype_multichoice";
	$r_far = "partiallycorrectfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_op->incorrectfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "qtype_multichoice";
	$r_far = "incorrectfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 1); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSEMRec($r_qst)
{
	global $DB;
	global $CFG;
	if ($r_qst->qtype != RWSMAT)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_fld = $r_qst->defaultmark;
	else
		$r_fld = $r_qst->defaultgrade;
	if ($r_fld < 0)
		$r_fld = 0;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = $r_qst->penalty;
	$r_fld = RWSDblOut($r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_op = $DB->get_record("question_match",
	  array("question" => $r_qst->id));
	if ($r_op === FALSE)
		return FALSE;
	$r_fld = $r_op->shuffleanswers;
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	$r_prs = array();
	$r_pis = explode(",", $r_op->subquestions);
	foreach($r_pis as $r_id) {
		$r_pr = $DB->get_record("question_match_sub", array("id" => $r_id));
		if ($r_pr === FALSE)
			return FALSE;
		$r_prs[] = $r_pr;
	}
	$r_fld = count($r_prs);
	$r_fld = pack("C", $r_fld);
	$r_rcd .= $r_fld;
	foreach($r_prs as $r_pr) {
		$r_txt = $r_pr->questiontext;
		$r_scr = "pluginfile.php";
		$r_cmp = "qtype_match";
		$r_far = "subquestion";
		$r_iti = $r_pr->id;
		$r_fld = file_rewrite_pluginfile_urls(
		  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
		  );
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
		$r_fld = $r_pr->answertext;
		if (!RWSIVUtf8($r_fld))
			$r_fld = utf8_encode($r_fld);
		$r_fld = pack("a*x", $r_fld);
		$r_rcd .= $r_fld;
	}
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 5); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSEDRec($r_qst)
{
	global $DB;
	if ($r_qst->qtype != RWSDES)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 6); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSEERec($r_qst)
{
	global $DB;
	global $CFG;
	if ($r_qst->qtype != RWSESS)
		return FALSE;
	if ($r_qst->parent != 0)
		return FALSE;
	$r_ctxi = $DB->get_field("question_categories", "contextid",
	  array("id" => $r_qst->category));
	$r_fld = $r_qst->name;
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd = $r_fld;
	$r_txt = $r_qst->questiontext;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "questiontext";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = "";
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
		$r_fld = $r_qst->defaultmark;
	else
		$r_fld = $r_qst->defaultgrade;
	if ($r_fld < 0)
		$r_fld = 0;
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_txt = $r_qst->generalfeedback;
	$r_scr = "pluginfile.php";
	$r_cmp = "question";
	$r_far = "generalfeedback";
	$r_iti = $r_qst->id;
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
		$r_op = $DB->get_record("qtype_essay_options",
		  array("questionid" => $r_qst->id));
		$r_txt = $r_op->graderinfo;
		$r_cmp = "qtype_essay";
		$r_far = "graderinfo";
		$r_iti = $r_qst->id;
	}
	else { 
		$r_asr = $DB->get_record("question_answers",
		  array("question" => $r_qst->id));
		if ($r_asr === FALSE)
			return FALSE;
		$r_txt = $r_asr->feedback;
		$r_scr = "pluginfile.php";
		$r_cmp = "question";
		$r_far = "answerfeedback";
		$r_iti = $r_asr->id;
	}
	$r_scr = "pluginfile.php";
	$r_fld = file_rewrite_pluginfile_urls(
	  $r_txt, $r_scr, $r_ctxi, $r_cmp, $r_far, $r_iti, null
	  );
	if (!RWSIVUtf8($r_fld))
		$r_fld = utf8_encode($r_fld);
	$r_fld = pack("a*x", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = 8; 
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = time();
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_fld = crc32($r_rcd);
	$r_fld = pack("N", $r_fld);
	$r_rcd .= $r_fld;
	$r_qd  = pack("C", 4); 
	$r_qd .= pack("N", strlen($r_rcd)); 
	$r_qd .= $r_rcd; 
	return $r_qd;
}
function RWSCEData($r_uf, $r_cf)
{
	$r_sps = array(
		basename($r_uf) => $r_uf
		);
	$r_pkr = get_file_packer("application/zip");
	$r_ok = $r_pkr->archive_to_pathname($r_sps, $r_cf);
	return $r_ok;
}
function RWSDIData($r_fdat, $r_imd)
{
	$r_clntf = FALSE;
	$r_tpp = RWSGTPath();
	$r_tpf = tempnam($r_tpp, "rws");
	$r_ok = ($r_tpf !== FALSE);
	if ($r_ok) {
		$r_ext = pathinfo($r_tpf, PATHINFO_EXTENSION);
		if (empty($r_ext)) {
			$r_onm = $r_tpf;
			$r_tpf .= ".tmp";
			if (file_exists($r_tpf))
				unlink($r_tpf);
			$r_ok = rename($r_onm, $r_tpf);
		}
	}
	if ($r_ok) {
		$r_tmp = fopen($r_tpf, "wb"); 
		$r_ok = ($r_tmp !== FALSE);
		$r_clntf = $r_ok;
	}
	if ($r_ok) {
		$r_by = fwrite($r_tmp, $r_fdat);
		$r_ok = ($r_by !== FALSE);
	}
	if ($r_clntf)
		fclose($r_tmp);
	if ($r_ok) {
		$r_pkr = get_file_packer("application/zip");
		$r_ress = $r_pkr->extract_to_pathname($r_tpf, $r_imd);
		if ($r_ress === FALSE)
			$r_ok = FALSE;
		if ($r_ok) {
			foreach ($r_ress as $r_nm => $r_status) {
				if ($r_status !== true) {
					$r_ok = FALSE;
					break;
				}
			}
		}
	}
	if ($r_clntf && file_exists($r_tpf))
		unlink($r_tpf);
	return $r_ok;
}
function RWSMTFldr()
{
	global $CFG;
	if (RWSFCmp($CFG->version, 2011120500.00, 2) >= 0) { 
		$r_tpp = make_temp_directory("rws" . time());
		return $r_tpp;
	}
	else { 
		$r_tpp = RWSGTPath();
		$r_ok = ($r_tpp !== FALSE);
		if ($r_ok) {
			$r_tpf = tempnam($r_tpp, "rws");
			$r_ok = ($r_tpf !== FALSE);
		}
		if ($r_ok && file_exists($r_tpf))
			$r_ok = unlink($r_tpf);
		if ($r_ok)
			$r_ok = mkdir($r_tpf);
		if ($r_ok)
			return $r_tpf;
		else
			return FALSE;
	}
}
function RWSEQCQues($r_qci, &$r_qfl, &$r_drp, $r_w64)
{
	global $DB;
    $r_drp = 0;
	$r_qd = "";
	$r_qtps = array();
	$r_qsts = $DB->get_records("question", array("category" => $r_qci));
	if (count($r_qsts) > 0) {
		foreach ($r_qsts as $r_q) {
			if ($r_q->parent == 0)
				$r_qtps[] = $r_q;
		}
	}
	if (count($r_qtps) < 1) {
		RWSSErr("2102");
	}
	$r_ran = 0;
	$r_qd = RWSEQues(
	  $r_qtps, $r_qfl, $r_drp, $r_ran, $r_w64);
	return $r_qd;
}
function RWSEQQues(
  $r_qzmi, &$r_qfl, &$r_drp, &$r_ran, $r_w64)
{
	global $DB;
    $r_drp = 0;
    $r_ran = 0;
	$r_mss = 0;
	$r_cmod = $DB->get_record("course_modules",
	  array("id" => $r_qzmi));
	if ($r_cmod === FALSE)
		RWSSErr("2042"); 
	$r_mr = $DB->get_record("modules",
	  array("id" => $r_cmod->module));
    if ($r_mr === FALSE) 
        RWSSErr("2043");
 	$r_qiz = $DB->get_record($r_mr->name,
	  array("id" => $r_cmod->instance));
	if ($r_qiz === FALSE) 
        RWSSErr("2044");
    $r_qd = "";
    $r_qis = explode(",", $r_qiz->questions);
	$r_qsts = array();
	if ($r_qis !== FALSE) {
		foreach ($r_qis as $r_id) {
			if ($r_id == "0")
				continue; 
			$r_q = $DB->get_record("question", array("id" => $r_id));
			if ($r_q !== FALSE)
				$r_qsts[] = $r_q;
			else
				$r_mss++;
		}
	}
	if (count($r_qsts) < 1) {
		RWSSErr("2103");
	}
	$r_qd = RWSEQues(
	  $r_qsts, $r_qfl, $r_drp, $r_ran, $r_w64);
	$r_drp += $r_mss;
	return $r_qd;
}
function RWSEQues(
  $r_qsts, &$r_qfl, &$r_drp, &$r_ran, $r_w64)
{
		$r_fv = 0; 
	$r_fnc = "rwsexportqdata.zip";
	$r_fnu = "rwsexportqdata.dat";
	$r_qfl = "";
	$r_exp = 0;
	$r_drp = 0;
	$r_ran = 0;
	$r_clned = FALSE;
	$r_clnef = FALSE;
	$r_clncf = FALSE;
	$r_cloef = FALSE;
	$r_ok = (count($r_qsts) > 0);
	if (!$r_ok)
		return "";
	if ($r_ok) {
		$r_exd = RWSMTFldr();
		$r_ok = ($r_exd !== FALSE);
		$r_clned = $r_ok;
		if (!$r_ok)
			$r_err = "2045"; 
	}
	if ($r_ok) {
		$r_exf = "$r_exd/$r_fnu";
		$r_hdl = fopen($r_exf, "wb"); 
		$r_ok = ($r_hdl !== FALSE);
		$r_clnef = $r_ok;
		$r_cloef = $r_ok;
		if (!$r_ok)
			$r_err = "2046"; 
	}
	if ($r_ok) {
			$r_dat = pack("C*", 0xc7, 0x89, 0xf0, 0x4c, 0xa4, 0x03, 0x47, 0x9b,
			  0xa3, 0x7b, 0x29, 0xc6, 0xad, 0xd5, 0x30, 0x81);
		$r_dat .= pack("n", $r_fv);
		$r_by = fwrite($r_hdl, $r_dat);
		$r_ok = ($r_by !== FALSE);
		if (!$r_ok)
			$r_err = "2047"; 
	}
	if ($r_ok) {
		$r_i = 0;
		foreach ($r_qsts as $r_q) {
			$r_i++;
			if ($r_i % 10 == 0) {
				$r_rcd = RWSERRec(time());
				$r_ok2 = ($r_rcd !== FALSE);
				if ($r_ok2)
					RWSWNQRec($r_hdl, $r_rcd);
			}
			switch ($r_q->qtype) {
			case RWSSHA:
				$r_rcd = RWSESARec($r_q);
				break;
			case RWSTRF:
				$r_rcd = RWSETFRec($r_q);
				break;
			case RWSMCH:
				$r_rcd = RWSEMCRec($r_q);
				break;
			case RWSMAT:
				$r_rcd = RWSEMRec($r_q);
				break;
			case RWSDES:
				$r_rcd = RWSEDRec($r_q);
				break;
			case RWSESS:
				$r_rcd = RWSEERec($r_q);
				break;
			case RWSCSI:
			case RWSCAL:
				$r_rcd = RWSECRec($r_q);
				break;
			case RWSMAN: 
				$r_rcd = RWSEMARec($r_q);
				break;
			case RWSRND:
				$r_ran++;
				$r_rcd = FALSE;
				break;
			case RWSCMU:
			case RWSNUM:
			case RWSRSM:
			default:
				$r_rcd = FALSE;
				break;
			}
			$r_ok2 = ($r_rcd !== FALSE);
			if ($r_ok2)
				$r_ok2 = RWSWNQRec($r_hdl, $r_rcd);
			if ($r_ok2)
				$r_exp++;
			else
				$r_drp++;
		}
    }
	if ($r_cloef)
		fclose($r_hdl);
	if ($r_ok && $r_exp > 0) {
		$r_cf = "$r_exd/$r_fnc";
		$r_ok = RWSCEData($r_exf, $r_cf);
		$r_clncf = $r_ok;
		if (!$r_ok)
			$r_err = "2048"; 
	}
	if ($r_ok && $r_exp > 0) {
		$r_cpr = file_get_contents($r_cf);
		$r_ok = ($r_cpr !== FALSE);
		if (!$r_ok)
			$r_err = "2049"; 
	}
	if ($r_ok && $r_exp > 0 && $r_w64)
		$r_ecd = base64_encode($r_cpr);
	if ($r_clnef && file_exists($r_exf))
		unlink($r_exf);
	if ($r_clncf && file_exists($r_cf))
		unlink($r_cf);
	if ($r_clned && file_exists($r_exd))
		rmdir($r_exd);
	if (!$r_ok)
		RWSSErr($r_err);
	if ($r_exp == 0) {
		RWSSErr("2104");
	}
	$r_qfl = $r_fnc;
	if ($r_w64)
		return $r_ecd;
	else
		return $r_cpr;
}
function RWSUQGrades($r_qiz)
{
	$r_gi = grade_item::fetch(array('itemtype'=>'mod',
	  'itemmodule'=>$r_qiz->modulename, 'iteminstance'=>$r_qiz->instance,
	  'itemnumber'=>0, 'courseid'=>$r_qiz->course));
     if ($r_gi && $r_gi->idnumber != $r_qiz->cmidnumber) {
         $r_gi->idnumber = $r_qiz->cmidnumber;
         $r_gi->update();
     }
    $r_its = grade_item::fetch_all(array('itemtype'=>'mod',
	  'itemmodule'=>$r_qiz->modulename, 'iteminstance'=>$r_qiz->instance,
	  'courseid'=>$r_qiz->course));
    if ($r_its && isset($r_qiz->gradecat)) {
        if ($r_qiz->gradecat == -1) {
            $r_gcat = new grade_category();
            $r_gcat->courseid = $r_qiz->course;
            $r_gcat->fullname = $r_qiz->name;
            $r_gcat->insert();
            if ($r_gi) {
                $r_par = $r_gi->get_parent_category();
                $r_gcat->set_parent($r_par->id);
            }
            $r_qiz->gradecat = $r_gcat->id;
        }
        foreach ($r_its as $r_iti=>$r_un) {
            $r_its[$r_iti]->set_parent($r_qiz->gradecat);
            if ($r_iti == $r_gi->id)
                $r_gi = $r_its[$r_iti]; 
        }
    }
    if ($r_ocs = grade_outcome::fetch_all_available($r_qiz->course)) {
        $r_gis = array();
        $r_mit = 999;
        if ($r_its) {
            foreach($r_its as $r_it) {
                if ($r_it->itemnumber > $r_mit)
                    $r_mit = $r_it->itemnumber;
            }
        }
        foreach($r_ocs as $r_oc) {
            $r_eln = 'outcome_'.$r_oc->id;
            if (property_exists($r_qiz, $r_eln) and $r_qiz->$r_eln) {
                if ($r_its) {
                    foreach($r_its as $r_it) {
                        if ($r_it->outcomeid == $r_oc->id)
                            continue 2; 
                    }
                }
                $r_mit++;
                $r_oi = new grade_item();
                $r_oi->courseid     = $r_qiz->course;
                $r_oi->itemtype     = 'mod';
                $r_oi->itemmodule   = $r_qiz->modulename;
                $r_oi->iteminstance = $r_qiz->instance;
                $r_oi->itemnumber   = $r_mit;
                $r_oi->itemname     = $r_oc->fullname;
                $r_oi->outcomeid    = $r_oc->id;
                $r_oi->gradetype    = GRADE_TYPE_SCALE;
                $r_oi->scaleid      = $r_oc->scaleid;
                $r_oi->insert();
                if ($r_gi) {
                    $r_oi->set_parent($r_gi->categoryid);
                    $r_oi->move_after_sortorder($r_gi->sortorder);
                } else if (isset($r_qiz->gradecat)) {
                    $r_oi->set_parent($r_qiz->gradecat);
                }
            }
        }
    }
}
function RWSDQCat($r_qci)
{
	global $DB;
	global $CFG;
	$r_chn = $DB->get_records("question_categories",
	  array("parent" => $r_qci));
	if (count($r_chn) > 0) {
		foreach ($r_chn as $r_chd)
			RWSDQCat($r_chd->id);
	}
	$r_qsts = $DB->get_records("question", array("category" => $r_qci));
	if (count($r_qsts) > 0) {
		foreach ($r_qsts as $r_q) {
			if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
				question_delete_question($r_q->id);
			else
				delete_question($r_q->id);
		}
		$DB->delete_records("question", array("category" => $r_qci));
	}
	$DB->delete_records("question_categories", array("id" => $r_qci));
}
function RWSIQCUsed($r_qci)
{
	global $DB;
	global $CFG;
	$r_chn = $DB->get_records("question_categories",
	  array("parent" => $r_qci));
	if (count($r_chn) > 0) {
		foreach ($r_chn as $r_chd) {
			if (RWSIQCUsed($r_chd->id))
				return TRUE;
		}
	}
	$r_qsts = $DB->get_records("question", array("category" => $r_qci));
	if (count($r_qsts) > 0) {
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
			$r_qis = array();
			foreach ($r_qsts as $r_q)
				$r_qis[] = $r_q->id;
			if (questions_in_use($r_qis))
				return TRUE;
		}
		else { 
			foreach ($r_qsts as $r_q) {
				if (count(question_list_instances($r_q->id)) > 0)
					return TRUE;
			}
		}
	}
	return FALSE;	
}
function RWSPAtt(
  $r_qtyp, $r_cid, $r_ctxi, $r_cmp, $r_far, $r_iti, $r_txt)
{
	global $USER;
	$r_l = strlen($r_txt);
	$r_out = "";
	$r_p = 0;
	$r_sctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_sup = "%%COURSEPATH%%";
	$r_dup = "@@PLUGINFILE@@";
	while ($r_p < $r_l)	{
		$r_nx = strpos($r_txt, "$r_sup/", $r_p);
		if ($r_nx === FALSE)
			break;
		$r_st = $r_p;
		$r_end = $r_nx;
		$r_out .= substr($r_txt, $r_st, $r_end - $r_st);
		$r_st = $r_nx + strlen("$r_sup/");
		$r_end = strpos($r_txt, "/", $r_st);
		if ($r_end === FALSE) {
			$r_end = $r_st;
			$r_st = $r_nx;
			$r_out .= substr($r_txt, $r_st, $r_end - $r_st);
			$r_p = $r_end;
			continue;
		}
		$r_ff = substr($r_txt, $r_st, $r_end - $r_st);
		$r_st = $r_end + 1;
		$r_end = strpos($r_txt, "\"", $r_st);
		if ($r_end === FALSE) {
			$r_end = $r_st;
			$r_st = $r_nx;
			$r_out .= substr($r_txt, $r_st, $r_end - $r_st);
			$r_p = $r_end;
			continue;
		}
		$r_fn = substr($r_txt, $r_st, $r_end - $r_st);
		$r_p = $r_end;
		$r_sctxid = $r_sctx->id;
		$r_scmp = "mod_respondusws";
		$r_sfar = "upload";
		$r_sitm = $USER->id;
		$r_sfip = "/$r_ff/";
		$r_sfnm = $r_fn;
		$r_dcxi = $r_ctxi;
		$r_dcmp = $r_cmp;
		$r_dfar = $r_far;
		$r_ditm = $r_iti;
		$r_dfip = "/";
		$r_dfnm = $r_fn;
		try {
			$r_fs = get_file_storage();
			$r_fl = $r_fs->get_file($r_sctxid, $r_scmp,
			  $r_sfar, $r_sitm, $r_sfip, $r_sfnm);
		} catch (Exception $r_e) {
			$r_fl = FALSE;
		}
		if ($r_fl === FALSE) {
			$r_st = $r_nx;
			$r_end = $r_p;
			$r_out .= substr($r_txt, $r_st, $r_end - $r_st);
			continue;
		}
		try {
			$r_fex = $r_fs->file_exists($r_dcxi, $r_dcmp,
			  $r_dfar, $r_ditm, $r_dfip, $r_dfnm);
			if ($r_fex == FALSE) {
				$r_finf = array(
				  "contextid" => $r_dcxi, "component" => $r_dcmp,
				  "filearea" => $r_dfar, "itemid" => $r_ditm,
				  "filepath" => $r_dfip, "filename" => $r_dfnm
				  );
				if ($r_fs->create_file_from_storedfile($r_finf, $r_fl))
					$r_fex = TRUE;
			}
		} catch (Exception $r_e) {
			$r_fex = FALSE;
		}
		if ($r_fex == FALSE) {
			$r_st = $r_nx;
			$r_end = $r_p;
			$r_out .= substr($r_txt, $r_st, $r_end - $r_st);
			continue;
		}
		$r_url = $r_dup . $r_dfip . $r_dfnm;
		$r_out .= $r_url;
	}
	if ($r_p < $r_l) {
		$r_st = $r_p;
		$r_end = $r_l;
		$r_out .= substr($r_txt, $r_st, $r_end - $r_st);
	}
	return $r_out;
}
function RWSIVUtf8($r_str)
{ 
	$r_l = strlen($r_str);
	$r_i = 0;
	while ($r_i < $r_l) {
		$r_c0 = ord($r_str[$r_i]);
		if ($r_i+1 < $r_l)
			$r_c1 = ord($r_str[$r_i+1]);
		if ($r_i+2 < $r_l)
			$r_c2 = ord($r_str[$r_i+2]);
		if ($r_i+3 < $r_l)
			$r_c3 = ord($r_str[$r_i+3]);
		if ($r_c0 >= 0x00 && $r_c0 <= 0x7e) {
			$r_i++;
		}
		else if ($r_i+1 < $r_l
		  && $r_c0 >= 0xc2 && $r_c0 <= 0xdf
		  && $r_c1 >= 0x80 && $r_c1 <= 0xbf) {
			$r_i += 2;
		}
		else if ($r_i+2 < $r_l
		  && $r_c0 == 0xe0
		  && $r_c1 >= 0xa0 && $r_c1 <= 0xbf
		  && $r_c2 >= 0x80 && $r_c2 <= 0xbf) {
			$r_i += 3;
		}
		else if ($r_i+2 < $r_l
		  && (($r_c0 >= 0xe1 && $r_c0 <= 0xec) || $r_c0 == 0xee || $r_c0 == 0xef)
		  && $r_c1 >= 0x80 && $r_c1 <= 0xbf
		  && $r_c2 >= 0x80 && $r_c2 <= 0xbf) {
			$r_i += 3;
		}
		else if ($r_i+2 < $r_l
		  && $r_c0 == 0xed
		  && $r_c1 >= 0x80 && $r_c1 <= 0x9f
		  && $r_c2 >= 0x80 && $r_c2 <= 0xbf) {
			$r_i += 3;
		}
		else if ($r_i+3 < $r_l
		  && $r_c0 == 0xf0
		  && $r_c1 >= 0x90 && $r_c1 <= 0xbf
		  && $r_c2 >= 0x80 && $r_c2 <= 0xbf
		  && $r_c3 >= 0x80 && $r_c3 <= 0xbf) {
			$r_i += 4;
		}
		else if ($r_i+3 < $r_l
		  && $r_c0 >= 0xf1 && $r_c0 <= 0xf3
		  && $r_c1 >= 0x80 && $r_c1 <= 0xbf
		  && $r_c2 >= 0x80 && $r_c2 <= 0xbf
		  && $r_c3 >= 0x80 && $r_c3 <= 0xbf) {
			$r_i += 4;
		}
		else if ($r_i+3 < $r_l
		  && $r_c0 == 0xf4
		  && $r_c1 >= 0x80 && $r_c1 <= 0x8f
		  && $r_c2 >= 0x80 && $r_c2 <= 0xbf
		  && $r_c3 >= 0x80 && $r_c3 <= 0xbf) {
			$r_i += 4;
		}
		else {
			return FALSE;
		}
	}
	return TRUE;
}
function RWSDSAct($r_ac)
{
	if ($r_ac == "phpinfo")
		RWSAPInfo();
	else if ($r_ac == "serviceinfo")
		RWSASInfo();
	else if ($r_ac == "login")
		RWSAILog();
	else if ($r_ac == "logout")
		RWSAOLog();
	else if ($r_ac == "courselist")
		RWSACList();
	else if ($r_ac == "sectionlist")
		RWSASList();
	else if ($r_ac == "quizlist")
		RWSAQList();
	else if ($r_ac == "qcatlist")
		RWSAQCList();
	else if ($r_ac == "addqcat")
		RWSAAQCat();
	else if ($r_ac == "deleteqcat")
		RWSADQCat();
	else if ($r_ac == "deletequiz")
		RWSADQuiz();
	else if ($r_ac == "addquiz")
		RWSAAQuiz();
	else if ($r_ac == "updatequiz")
		RWSAUQuiz();
	else if ($r_ac == "addqlist")
		RWSAAQList();
	else if ($r_ac == "addqrand")
		RWSAAQRand();
	else if ($r_ac == "importqdata")
		RWSAIQData();
	else if ($r_ac == "getquiz")
		RWSAGQuiz();
	else if ($r_ac == "exportqdata")
		RWSAEQData();
	else if ($r_ac == "uploadfile")
		RWSAUFile();
	else if ($r_ac == "dnloadfile")
		RWSADFile();
	else
		RWSSErr("2050");
}
function RWSAPInfo()
{
	RWSCMAuth();
	RWSCMUSvc();
	if (!is_siteadmin()) {
		RWSSErr("2107");
	}
	phpinfo();
	exit;
}
function RWSASInfo()
{
	global $CFG;
	global $RWSLB;
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_ilg = isloggedin();
	$r_ia = is_siteadmin();
	$r_su = RWSGSUrl(FALSE, TRUE);
	$r_ver = "";
	$r_rel = "";
	$r_req = "";
	$r_lat = "";
	$r_vf = RWSGMPath() . "/version.php";
	if (is_readable($r_vf))
		include($r_vf);
	if ($module) {
		if (!empty($module->version))
			$r_ver = $module->version;
		if (!empty($module->rws_release))
			$r_rel = $module->rws_release;
		if (!empty($module->requires))
			$r_req = $module->requires;
		if (!empty($module->requires))
			$r_req = $module->requires;
		if (!empty($module->rws_latest))
			$r_lat = $module->rws_latest;
	}
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_info>\r\n";
	if ($r_ia)
		echo "\t<description>Respondus 4.0 Web Service Extension For Moodle</description>\r\n";
	else
		echo "\t<description>(authentication required)</description>\r\n";
	if (!empty($r_ver)) {
		echo "\t<module_version>";
		if ($r_bv >= 2010042801) 
			echo utf8_encode(htmlspecialchars($r_ver));
		else 
			echo "2009093000";
		echo "</module_version>\r\n";
	}
	else
		echo "\t<module_version />\r\n";
	if (!empty($r_rel)) {
		echo "\t<module_release>";
		if ($r_bv >= 2010042801) 
			echo utf8_encode(htmlspecialchars($r_rel));
		else 
			echo "1.0.2";
		echo "</module_release>\r\n";
	}
	else
		echo "\t<module_release />\r\n";
	if ($r_bv >= 2010042801) { 
		echo "\t<module_behavior>";
		echo utf8_encode(htmlspecialchars($r_bv));
		echo "</module_behavior>\r\n";
	}
	if ($r_ia) {
		if (!empty($r_req)) {
			echo "\t<module_requires>";
			echo utf8_encode(htmlspecialchars($r_req));
			echo "</module_requires>\r\n";
		}
		else
			echo "\t<module_requires />\r\n";
	}
	else
		echo "\t<module_requires>(authentication required)</module_requires>\r\n";
	if ($r_ia) {
		if (!empty($r_lat)) {
			echo "\t<module_latest>";
			echo utf8_encode(htmlspecialchars($r_lat));
			echo "</module_latest>\r\n";
		}
		else
			echo "\t<module_latest />\r\n";
	}
	else
		echo "\t<module_latest>(authentication required)</module_latest>\r\n";
	if ($r_ia) {
		echo "\t<endpoint>";
		echo utf8_encode(htmlspecialchars($r_su));
		echo "</endpoint>\r\n";
	}
	else
		echo "\t<endpoint>(authentication required)</endpoint>\r\n";
	if ($r_ia) {
		echo "\t<whoami>";
		echo utf8_encode(htmlspecialchars(exec("whoami")));
		echo "</whoami>\r\n";
	}
	else
		echo "\t<whoami>(authentication required)</whoami>\r\n";
	if ($r_ilg) {
		echo "\t<moodle_version>";
		echo utf8_encode(htmlspecialchars($CFG->version));
		echo "</moodle_version>\r\n";
	}
	else
		echo "\t<moodle_version>(authentication required)</moodle_version>\r\n";
	if ($r_ilg) {
		echo "\t<moodle_release>";
		echo utf8_encode(htmlspecialchars($CFG->release));
		echo "</moodle_release>\r\n";
	}
	else
		echo "\t<moodle_release>(authentication required)</moodle_release>\r\n";
	if ($r_ia) {
		echo "\t<moodle_site_id>";
		echo utf8_encode(htmlspecialchars(SITEID));
		echo "</moodle_site_id>\r\n";
	}
	else
		echo "\t<moodle_site_id>(authentication required)</moodle_site_id>\r\n";
	if ($r_ia) {
		echo "\t<moodle_maintenance>";
		if (!empty($CFG->maintenance_enabled)
		  || file_exists($CFG->dataroot . "/" . SITEID . "/maintenance.html"))
			echo "yes";
		else
			echo "no";
		echo "</moodle_maintenance>\r\n";
	}
	else if ($r_bv >= 2010063001) 
		echo "\t<moodle_maintenance>(authentication required)</moodle_maintenance>\r\n";
	else 
		echo "\t<moodle_maintenance>no</moodle_maintenance>\r\n";
	if ($r_ia) {
		$r_mn = get_list_of_plugins("mod");
		if ($r_mn && count($r_mn) > 0) {
			$r_ml = implode(",", $r_mn);
			echo "\t<moodle_module_types>";
			echo utf8_encode(htmlspecialchars(trim($r_ml)));
			echo "</moodle_module_types>\r\n";
		}
		else
			echo "\t<moodle_module_types />\r\n";
	}
	else
		echo "\t<moodle_module_types>(authentication required)</moodle_module_types>\r\n";
	$r_qtn = get_list_of_plugins("question/type");
	if (!$r_qtn)
		$r_qtn = array();
	$r_irx = FALSE;
	if (count($r_qtn) > 0) {
		foreach ($r_qtn as $r_qn) {
			if (strcasecmp($r_qn, RWSRXP) == 0) {
				$r_irx = TRUE;
				break;
			}
		}
	}
	if ($r_ia) {
		if (count($r_qtn) > 0) {
			$r_qtl = implode(",", $r_qtn);
			echo "\t<moodle_question_types>";
			echo utf8_encode(htmlspecialchars(trim($r_qtl)));
			echo "</moodle_question_types>\r\n";
		}
		else
			echo "\t<moodle_question_types />\r\n";
	}
	else
		echo "\t<moodle_question_types>(authentication required)</moodle_question_types>\r\n";
	if ($r_ilg) {
		echo "\t<cloze_regexp_support>";
		$r_pth = "$CFG->dirroot/question/type/multianswer/questiontype.php";
		$r_dat = file_get_contents($r_pth);
		if ($r_dat !== FALSE
		  && strpos($r_dat, "ANSWER_REGEX_ANSWER_TYPE_REGEXP") !== FALSE) {
			if ($r_bv >= 2010063001) { 
				if ($r_irx)
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
	else if ($r_bv >= 2010063001) 
		echo "\t<cloze_regexp_support>(authentication required)</cloze_regexp_support>\r\n";
	else 
		echo "\t<cloze_regexp_support>no</cloze_regexp_support>\r\n";
	if ($r_ilg) {
		echo "\t<ldb_module_detected>";
		if ($RWSLB->mex || $RWSLB->bex)
			echo "yes";
		else
			echo "no";
		echo "</ldb_module_detected>\r\n";
	}
	else if ($r_bv >= 2010063001) 
		echo "\t<ldb_module_detected>(authentication required)</ldb_module_detected>\r\n";
	else 
		echo "\t<ldb_module_detected>no</ldb_module_detected>\r\n";
	if ($r_ilg) {
		echo "\t<ldb_module_ok>";
		if ($RWSLB->mok || $RWSLB->bok)
			echo "yes";
		else
			echo "no";
		echo "</ldb_module_ok>\r\n";
	}
	else if ($r_bv >= 2010063001) 
		echo "\t<ldb_module_ok>(authentication required)</ldb_module_ok>\r\n";
	else 
		echo "\t<ldb_module_ok>no</ldb_module_ok>\r\n";
	echo "</service_info>\r\n";
	exit;
}
function RWSFCmp($r_f1, $r_f2, $r_pre)
{
	if ($r_pre < 0)
		$r_pre = 0;
	$r_eps = 1 / pow(10, $r_pre);
	$r_dif = ($r_f1 - $r_f2);
	if (abs($r_dif) < $r_eps)
		return 0;
	else if ($r_dif < 0)
		return -1;
	else
		return 1;
}
function RWSDblOut($r_val)
{
	$r_t = unpack("C*", pack("S", 256));
	$r_chrs = array_values(unpack("C*", pack("d", $r_val)));
	if($r_t[1] == 1) {
		$r_by = $r_chrs;
	} else {
		$r_by = array_reverse($r_chrs);
	}
	$r_bn = "";
	foreach ($r_by as $r_b)
		$r_bn .= pack("C", $r_b);
	return $r_bn;
}
function RWSDblIn($r_val)
{
	$r_t = unpack("C*", pack("S", 256));
	$r_by = array_values(unpack("C*", $r_val));
	if($r_t[1] == 1) {
		$r_chrs = $r_by;
	} else {
		$r_chrs = array_reverse($r_by);
	}
	$r_bn = "";
	foreach ($r_chrs as $r_c)
		$r_bn .= pack("C", $r_c);
	$r_d = unpack("d", $r_bn);
	return $r_d[1];
}
function RWSGCFCat($r_ctx)
{
	global $DB;
	switch($r_ctx->contextlevel) {
	case CONTEXT_COURSE:
		$r_cid = $r_ctx->instanceid;
		break;
	case CONTEXT_MODULE:
		$r_cid = $DB->get_field("course_modules", "course",
			array("id" => $r_ctx->instanceid));
		if ($r_cid === FALSE) {
			RWSSErr("2111");
		}
		break;
	case CONTEXT_COURSECAT:
	case CONTEXT_SYSTEM:
		$r_cid = SITEID;
		break;
	default: 
		RWSSErr("2053");
	}
	return $r_cid;
}
function RWSAILog()
{
	global $CFG;
	global $RWSIHLOG;
	if (!$RWSIHLOG) {
		if ($CFG->loginhttps && !$CFG->sslproxy) {
			if (!isset($_SERVER["HTTPS"])
			  || empty($_SERVER["HTTPS"])
			  || strcasecmp($_SERVER["HTTPS"], "off") == 0) {
				RWSSErr("4001"); 
			}
		}
	}
	$r_usrn = RWSGSOpt("username");
	if ($r_usrn === FALSE || strlen($r_usrn) == 0)
		RWSSErr("2054"); 
	$r_pw = RWSGSOpt("password");
	if ($r_pw === FALSE || strlen($r_pw) == 0)
		RWSSErr("2055"); 
	if (isloggedin())
		RWSSErr("2056"); 
	RWSAMUser($r_usrn, $r_pw, FALSE);
}
function RWSAOLog()
{
	RWSCMAuth();
	RWSLMUser();
}
function RWSPLOCas($r_csp)
{
	global $RWSESL3;
	if (isset($_SESSION['rwscas']['cookiejar']))
		$r_ckf = $_SESSION['rwscas']['cookiejar'];
	if (empty($r_csp->config->hostname)
	  || !$r_csp->config->logoutcas) {
		if (isset($r_ckf)) {
			if (file_exists($r_ckf))
				unlink($r_ckf);
			unset($_SESSION['rwscas']['cookiejar']);
		}
		unset($_SESSION['rwscas']);
		return;
	}
	list($r_v1, $r_v2, $r_v3) = explode(".", phpCAS::getVersion());
	$r_csp->connectCAS();
	$r_lou = phpCAS::getServerLogoutURL();
	$r_ch = curl_init();
	curl_setopt($r_ch, CURLOPT_URL, $r_lou);
	curl_setopt($r_ch, CURLOPT_HTTPGET, TRUE);
	curl_setopt($r_ch, CURLOPT_RETURNTRANSFER, TRUE);
	curl_setopt($r_ch, CURLOPT_FOLLOWLOCATION, TRUE);
	curl_setopt($r_ch, CURLOPT_FAILONERROR, TRUE);
	curl_setopt($r_ch, CURLOPT_TIMEOUT, 30); 
	curl_setopt($r_ch, CURLOPT_SSL_VERIFYHOST, FALSE);
	curl_setopt($r_ch, CURLOPT_SSL_VERIFYPEER, FALSE);
	curl_setopt($r_ch, CURLOPT_USERAGENT, "PHP");
	if (isset($r_ckf)) {
		curl_setopt($r_ch, CURLOPT_COOKIEFILE, $r_ckf); 
		curl_setopt($r_ch, CURLOPT_COOKIEJAR, $r_ckf);  
	}
	curl_exec($r_ch);
	curl_close($r_ch);
	if (isset($r_ckf)) {
		if (file_exists($r_ckf))
			unlink($r_ckf);
		unset($_SESSION['rwscas']['cookiejar']);
	}
	unset($_SESSION['rwscas']);
	session_unset();
	session_destroy();
}
function RWSACList()
{
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_crss = RWSGUMCList();
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($r_crss) == 0) {
		echo "<courselist />\r\n";
		exit;
	}
	echo "<courselist>\r\n";
	foreach ($r_crss as $r_c) {
		echo "\t<course>\r\n";
		echo "\t\t<name>";
		echo utf8_encode(htmlspecialchars(trim($r_c->fullname)));
		echo "</name>\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($r_c->id)));
		echo "</id>\r\n";
		echo "\t</course>\r\n";
	}
	echo "</courselist>\r\n";
	exit;
}
function RWSASList()
{
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2057"); 
	$r_cid = intval($r_pm);
	$r_crs = RWSCMUCourse($r_cid);
	$r_secs = RWSGUVSList($r_cid);
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($r_secs) == 0) {
		echo "<sectionlist />\r\n";
		exit;
	}
	echo "<sectionlist>\r\n";
	if ($r_bv < 2011020100) { 
		$r_fnm = get_generic_section_name($r_crs->format, $r_secs[0]);
		$r_p = strrpos($r_fnm, " ");
		if ($r_p !== FALSE) 
			$r_fnm = substr($r_fnm, 0, $r_p);
		echo "\t<format_name>";
		echo utf8_encode(htmlspecialchars(trim($r_fnm)));
		echo "</format_name>\r\n";
	}
	foreach ($r_secs as $r_s) {
		echo "\t<section>\r\n";
		if ($r_bv >= 2011020100) { 
			$r_nm = get_section_name($r_crs, $r_s);
			echo "\t\t<name>";
			echo utf8_encode(htmlspecialchars($r_nm));
			echo "</name>\r\n";
		}
		$r_sum = trim($r_s->summary);
		if (strlen($r_sum) > 0) {
			echo "\t\t<summary>";
			echo utf8_encode(htmlspecialchars($r_sum));
			echo "</summary>\r\n";
		}
		else
			echo "\t\t<summary />\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($r_s->id)));
		echo "</id>\r\n";
		echo "\t\t<relative_index>";
		echo utf8_encode(htmlspecialchars(trim($r_s->section)));
		echo "</relative_index>\r\n";
		echo "\t</section>\r\n";
	}
	echo "</sectionlist>\r\n";
	exit;
}
function RWSAQList()
{
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2057"); 
	$r_cid = intval($r_pm);
	RWSCMUCourse($r_cid);
	$r_vqzs = RWSGUVQList($r_cid);
	if (count($r_vqzs) > 0)
		$r_mqzs = RWSGUMQList($r_vqzs);
	else
		$r_mqzs = array();
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($r_vqzs) == 0) {
		echo "<quizlist />\r\n";
		exit;
	}
	echo "<quizlist>\r\n";
	foreach ($r_vqzs as $r_q) {
		echo "\t<quiz>\r\n";
		echo "\t\t<name>";
		echo utf8_encode(htmlspecialchars(trim($r_q->name)));
		echo "</name>\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($r_q->id)));
		echo "</id>\r\n";
		echo "\t\t<section_id>";
		echo utf8_encode(htmlspecialchars(trim($r_q->section)));
		echo "</section_id>\r\n";
		echo "\t\t<writable>";
		if (in_array($r_q, $r_mqzs))
			echo "yes";
		else
			echo "no";
		echo "</writable>\r\n";
		echo "\t</quiz>\r\n";
	}
	echo "</quizlist>\r\n";
	exit;
}
function RWSAQCList()
{
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_rv = RWSGSOpt("version");
	if ($r_rv === FALSE || strlen($r_rv) == 0)
		$r_bv = 2009093000;	
	else
		$r_bv = intval($r_rv);
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2057"); 
	$r_cid = intval($r_pm);
	RWSCMUCourse($r_cid);
	$r_qcs = RWSGUQCats($r_cid);
	if ($r_bv >= 2010063001) { 
		foreach ($r_qcs as $r_qc) {
			$r_ctx = get_context_instance_by_id($r_qc->contextid);
			$r_qc->ci = RWSGCFCat($r_ctx);
		}
	}
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	if (count($r_qcs) == 0) {
		echo "<qcatlist />\r\n";
		exit;
	}
	echo "<qcatlist>\r\n";
	foreach ($r_qcs as $r_qc) {
		echo "\t<category>\r\n";
		echo "\t\t<name>";
		echo utf8_encode(htmlspecialchars(trim($r_qc->name)));
		echo "</name>\r\n";
		echo "\t\t<id>";
		echo utf8_encode(htmlspecialchars(trim($r_qc->id)));
		echo "</id>\r\n";
		if (!empty($r_qc->parent) && array_key_exists($r_qc->parent, $r_qcs)) {
			echo "\t\t<parent_id>";
			echo utf8_encode(htmlspecialchars(trim($r_qc->parent)));
			echo "</parent_id>\r\n";
		}
		if ($r_bv >= 2010063001) { 
			if ($r_qc->ci == SITEID) 
				echo "\t\t<system>yes</system>\r\n";
			else
				echo "\t\t<system>no</system>\r\n";
		}
		echo "\t</category>\r\n";
	}
	echo "</qcatlist>\r\n";
	exit;
}
function RWSAAQCat()
{
	global $DB;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("name");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2058"); 
	$r_qcn = trim(clean_text(strip_tags($r_pm, "<lang><span>")));
	if (strlen($r_qcn) > 254) {
		RWSSErr("2059");
	}
	$r_cid = FALSE;
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm !== FALSE && strlen($r_pm) > 0)
		$r_cid = intval($r_pm);
	$r_pi = FALSE;
	$r_pm = RWSGSOpt("parentid");
	if ($r_pm !== FALSE && strlen($r_pm) > 0)
		$r_pi = intval($r_pm);
	if ($r_cid === FALSE && $r_pi === FALSE) {
		RWSSErr("2060");
	}
	else if ($r_cid !== FALSE && $r_pi === FALSE) {
		RWSCMUCourse($r_cid);
		$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
		$r_pi = 0;
	}
	else if ($r_cid === FALSE && $r_pi !== FALSE) {
		$r_rcd = $DB->get_record("question_categories",
		  array("id" => $r_pi));
		if ($r_rcd === FALSE) {
			RWSSErr("2061");
		}
		$r_ctx = get_context_instance_by_id($r_rcd->contextid);
		$r_cid = RWSGCFCat($r_ctx);
		RWSCMUCourse($r_cid);
		if ($r_cid == SITEID)
			$r_ctx = get_context_instance(CONTEXT_SYSTEM);
		else
			$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	}
	else 
	{
		RWSCMUCourse($r_cid);
		$r_rcd = $DB->get_record("question_categories",
		  array("id" => $r_pi));
		if ($r_rcd === FALSE) {
			RWSSErr("2061");
		}
		$r_ctx = get_context_instance_by_id($r_rcd->contextid);
		$r_qcci = RWSGCFCat($r_ctx);
		if ($r_qcci != $r_cid) {
			if (is_siteadmin()) {
				if ($r_qcci != SITEID) {
					RWSSErr("2110");
				}
				else
					$r_ctx = $r_sys;
			}
			else {
				RWSSErr("2062");
			}
		}
		else
			$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	}
    $r_qca = new stdClass();
    $r_qca->parent = $r_pi;
    $r_qca->contextid = $r_ctx->id;
    $r_qca->name = $r_qcn;
    $r_qca->info = "Created by Respondus";
	$r_qca->infoformat = FORMAT_HTML;
    $r_qca->sortorder = 999;
    $r_qca->stamp = make_unique_id_code();
	$r_qci = $DB->insert_record("question_categories", $r_qca);
	rebuild_course_cache($r_cid);
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<addqcat>\r\n";
	echo "\t<name>";
	echo utf8_encode(htmlspecialchars(trim($r_qcn)));
	echo "</name>\r\n";
	echo "\t<id>";
	echo utf8_encode(htmlspecialchars(trim($r_qci)));
	echo "</id>\r\n";
	if ($r_pi != 0) {
		echo "\t<parent_id>";
		echo utf8_encode(htmlspecialchars(trim($r_pi)));
		echo "</parent_id>\r\n";
	}
	echo "</addqcat>\r\n";
	exit;
}
function RWSADQCat()
{
	global $DB;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("qcatid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2064"); 
	$r_qci = intval($r_pm);
	$r_qca = $DB->get_record("question_categories", array("id" => $r_qci));
	if ($r_qca === FALSE) 
		RWSSErr("2065");
	$r_ctx = get_context_instance_by_id($r_qca->contextid);
	$r_cid = RWSGCFCat($r_ctx);
	RWSCMUCourse($r_cid);
	question_can_delete_cat($r_qci);
	if (RWSIQCUsed($r_qci)) {
		RWSSErr("2066");
	}
	RWSDQCat($r_qci);
	rebuild_course_cache($r_cid);
	RWSSStat("1002"); 
}
function RWSADQuiz()
{
	global $RWSLB;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("quizid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2067"); 
	$r_qzmi = intval($r_pm);
	$r_rcd = RWSCMUQuiz($r_qzmi);
	$r_cid = $r_rcd->course;
	RWSCMUCourse($r_cid, TRUE);
	if (!quiz_delete_instance($r_rcd->instance)) {
		RWSSErr("2068");
	}
	if (!delete_course_module($r_qzmi)) {
		RWSSErr("2069");
	}
	if (!delete_mod_from_section($r_qzmi, $r_rcd->section)) {
		RWSSErr("2070");
	}
	if ($RWSLB->mok)
		lockdown_delete_options($r_rcd->instance);
	else if ($RWSLB->bok)
		lockdown_delete_options($r_rcd->instance);
	rebuild_course_cache($r_cid);
	RWSSStat("1003"); 
}
function RWSAAQuiz()
{
	global $CFG;
	global $DB;
	global $RWSLB;
	global $USER;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2057"); 
	$r_cid = intval($r_pm);
	$r_crs = RWSCMUCourse($r_cid, TRUE);
	$r_si = FALSE;
	$r_pm = RWSGSOpt("sectionid");
	if ($r_pm !== FALSE && strlen($r_pm) > 0)
		$r_si = intval($r_pm);
	if ($r_si === FALSE) {
		$r_sr = 0; 
	}
	else {
		$r_sec = $DB->get_record("course_sections",
		  array("id" => $r_si));
		if ($r_sec === FALSE)
			RWSSErr("2071"); 
		if ($r_sec->course != $r_cid) {
			RWSSErr("2072");
		}
		$r_sr = $r_sec->section;
	}
	$r_pm = RWSGSOpt("name");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2073"); 
	$r_qzn = trim(clean_text(strip_tags($r_pm, "<lang><span>")));
	$r_sfl = RWSGSOpt("sfile");
	if ($r_sfl === FALSE) {
		$r_sn = RWSGSOpt("sname");
		$r_sd = RWSGSOpt("sdata");
		$r_ecd = TRUE;
	}
	else {
		$r_sn = $r_sfl->filename;
		$r_sd = $r_sfl->filedata;
		$r_ecd = FALSE;
	}
	$r_imp = FALSE;
	if ($r_sd !== FALSE && strlen($r_sd) > 0) {
		if ($r_sn === FALSE || strlen($r_sn) == 0) {
			RWSSErr("2075");
		}
		$r_sn = clean_filename($r_sn);
		$r_imp = TRUE;
	}
	$r_mr = $DB->get_record("modules", array("name" => "quiz"));
	if ($r_mr === FALSE)
		RWSSErr("2074"); 
    $r_qiz = new stdClass();
	$r_qiz->name = $r_qzn;
	$r_qiz->section = $r_sr;
	$r_qiz->course = $r_cid;
	$r_qiz->coursemodule = 0;	
	$r_qiz->instance = 0;		
	$r_qiz->id = 0;				
	$r_qiz->modulename = $r_mr->name;
	$r_qiz->module = $r_mr->id;
	$r_qiz->groupmembersonly = 0;
	if (RWSFCmp($CFG->version, 2011120500.00, 2) >= 0) 
		$r_qiz->showdescription = 0; 
	$r_cpl = new completion_info($r_crs);
	if ($r_cpl->is_enabled()) {
		$r_qiz->completion = COMPLETION_TRACKING_NONE;
		$r_qiz->completionview = COMPLETION_VIEW_NOT_REQUIRED;
		$r_qiz->completiongradeitemnumber = null;
		$r_qiz->completionexpected = 0; 
	}
	if ($CFG->enableavailability) {
		$r_qiz->availablefrom = 0; 
		$r_qiz->availableuntil = 0; 
		if ($r_qiz->availableuntil) { 
			$r_qiz->availableuntil = strtotime("23:59:59",
			  $r_qiz->availableuntil);
		}
		$r_qiz->showavailability = CONDITION_STUDENTVIEW_HIDE;
	}
	RWSSQDefs($r_qiz);
	if ($r_imp)
		RWSIQSet($r_qiz, $r_sn, $r_sd, $r_ecd);
	if (is_null($r_qiz->quizpassword) && !is_null($r_qiz->password))
		$r_qiz->quizpassword = $r_qiz->password;
	$r_qzmi = add_course_module($r_qiz);
	if (!$r_qzmi) 
		RWSSErr("2077");
	$r_qiz->coursemodule = $r_qzmi;
	$r_insi = quiz_add_instance($r_qiz); 
	if (!$r_insi || is_string($r_insi)) {
		RWSSErr("2076");
	}
	$r_qiz->instance = $r_insi;
	$r_siu = add_mod_to_section($r_qiz);
	if (!$r_siu) 
		RWSSErr("2078");
    $DB->set_field("course_modules", "section", $r_siu,
	  array("id" => $r_qzmi));
	if ($r_si !== FALSE && $r_siu != $r_si) {
		RWSSErr("2078");
	}
	RWSSLBSet($r_qiz);
    set_coursemodule_visible($r_qzmi, $r_qiz->visible);
	if (isset($r_qiz->cmidnumber))  
		set_coursemodule_idnumber($r_qzmi, $r_qiz->cmidnumber);
	RWSUQGrades($r_qiz);
	if ($CFG->enableavailability) {
	}
	$r_evt = new stdClass();
	$r_evt->modulename = $r_qiz->modulename;
	$r_evt->name = $r_qiz->name;
	$r_evt->cmid = $r_qiz->coursemodule;
	$r_evt->courseid = $r_qiz->course;
	$r_evt->userid = $USER->id;
	events_trigger("mod_created", $r_evt);
	rebuild_course_cache($r_cid);
    grade_regrade_final_grades($r_cid);
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<addquiz>\r\n";
	echo "\t<name>";
	echo utf8_encode(htmlspecialchars(trim($r_qiz->name)));
	echo "</name>\r\n";
	echo "\t<id>";
	echo utf8_encode(htmlspecialchars(trim($r_qzmi)));
	echo "</id>\r\n";
	echo "\t<section_id>";
	echo utf8_encode(htmlspecialchars(trim($r_siu)));
	echo "</section_id>\r\n";
	echo "\t<writable>yes</writable>\r\n";
	if ($RWSLB->mex || $RWSLB->bex) {
		if ($RWSLB->mok) {
			if ($RWSLB->perr) 
				echo "\t<service_warning>3003</service_warning>\r\n";
		} else if ($RWSLB->bok) {
			if ($RWSLB->perr) 
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
function RWSAUQuiz()
{
	global $CFG;
	global $DB;
	global $RWSLB;
	global $USER;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("quizid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2067"); 
	$r_qzmi = intval($r_pm);
	$r_cmod = RWSCMUQuiz($r_qzmi);
	$r_sfl = RWSGSOpt("sfile");
	if ($r_sfl === FALSE) {
		$r_sn = RWSGSOpt("sname");
		$r_sd = RWSGSOpt("sdata");
		$r_ecd = TRUE;
	}
	else {
		$r_sn = $r_sfl->filename;
		$r_sd = $r_sfl->filedata;
		$r_ecd = FALSE;
	}
	$r_imp = FALSE;
	if ($r_sd !== FALSE && strlen($r_sd) > 0) {
		if ($r_sn === FALSE || strlen($r_sn) == 0) {
			RWSSErr("2075");
		}
		$r_sn = clean_filename($r_sn);
		$r_imp = TRUE;
	}
	$r_cid = $r_cmod->course;
	$r_crs = RWSCMUCourse($r_cid, TRUE);
	$r_mr = $DB->get_record("modules",
	  array("id" => $r_cmod->module));
    if ($r_mr === FALSE) 
        RWSSErr("2043");
	$r_qiz = $DB->get_record($r_mr->name,
	  array("id" => $r_cmod->instance));
	if ($r_qiz === FALSE) 
        RWSSErr("2044");
	$r_ren = FALSE;
	$r_pm = RWSGSOpt("rename");
	if ($r_pm !== FALSE && strlen($r_pm) > 0) {
		$r_ren = trim(clean_text(strip_tags($r_pm, "<lang><span>")));
		$r_qiz->name = $r_ren;
	}
	if ($r_ren === FALSE) {
		if ($r_sd === FALSE || strlen($r_sd) == 0)
			RWSSErr("2080"); 
	}
	$r_sec = $DB->get_record("course_sections",
	  array("id" => $r_cmod->section));
	if ($r_sec === FALSE) {
        RWSSErr("2079");
	}
    $r_qiz->coursemodule = $r_cmod->id;
    $r_qiz->section = $r_sec->section;
    $r_qiz->visible = $r_cmod->visible;
    $r_qiz->cmidnumber = $r_cmod->idnumber;
    $r_qiz->groupmode = groups_get_activity_groupmode($r_cmod);
    $r_qiz->groupingid = $r_cmod->groupingid;
    $r_qiz->groupmembersonly = $r_cmod->groupmembersonly;
    $r_qiz->course = $r_cid;
    $r_qiz->module = $r_mr->id;
    $r_qiz->modulename = $r_mr->name;
    $r_qiz->instance = $r_cmod->instance;
	if (RWSFCmp($CFG->version, 2011120500.00, 2) >= 0) 
		$r_qiz->showdescription = 0; 
	$r_cpl = new completion_info($r_crs);
	if ($r_cpl->is_enabled()) {
		$r_qiz->completion = $r_cmod->completion;
		$r_qiz->completionview = $r_cmod->completionview;
		$r_qiz->completionexpected = $r_cmod->completionexpected;
		$r_qiz->completionusegrade =
		  is_null($r_cmod->completiongradeitemnumber) ? 0 : 1;
	}
	if ($CFG->enableavailability) {
		$r_qiz->availablefrom = $r_cmod->availablefrom;
		$r_qiz->availableuntil = $r_cmod->availableuntil;
		if ($r_qiz->availableuntil) { 
			$r_qiz->availableuntil = strtotime("23:59:59",
			  $r_qiz->availableuntil);
		}
		$r_qiz->showavailability = $r_cmod->showavailability;
	}
	$r_its = grade_item::fetch_all(array('itemtype'=>'mod',
	  'itemmodule'=>$r_qiz->modulename, 'iteminstance'=>$r_qiz->instance,
	  'courseid'=>$r_cid));
	if ($r_its) {
        foreach ($r_its as $r_it) {
            if (!empty($r_it->outcomeid))
                $r_qiz->{'outcome_'.$r_it->outcomeid} = 1;
        }
        $r_gc = false;
        foreach ($r_its as $r_it) {
            if ($r_gc === false) {
                $r_gc = $r_it->categoryid;
                continue;
            }
            if ($r_gc != $r_it->categoryid) { 
                $r_gc = false;
                break;
            }
        }
        if ($r_gc !== false) 
            $r_qiz->gradecat = $r_gc;
    }
	if ($r_imp)
		RWSIQSet($r_qiz, $r_sn, $r_sd, $r_ecd);
	$DB->update_record("course_modules", $r_qiz);
	if (is_null($r_qiz->quizpassword) && !is_null($r_qiz->password))
		$r_qiz->quizpassword = $r_qiz->password;
	$r_res = quiz_update_instance($r_qiz);
	if (!$r_res || is_string($r_res)) {
		RWSSErr("2081");
	}
	RWSSLBSet($r_qiz);
	set_coursemodule_visible($r_qzmi, $r_qiz->visible);
	if (isset($r_qiz->cmidnumber))
		set_coursemodule_idnumber($r_qzmi, $r_qiz->cmidnumber);
	RWSUQGrades($r_qiz);
	if ($CFG->enableavailability) {
	}
	if ($r_cpl->is_enabled() && !empty($r_qiz->completionunlocked))
		$r_cpl->reset_all_state($r_qiz);
	$r_evt = new stdClass();
	$r_evt->modulename = $r_qiz->modulename;
	$r_evt->name = $r_qiz->name;
	$r_evt->cmid = $r_qiz->coursemodule;
	$r_evt->courseid = $r_qiz->course;
	$r_evt->userid = $USER->id;
	events_trigger("mod_updated", $r_evt);
	rebuild_course_cache($r_cid);
    grade_regrade_final_grades($r_cid);
	if ($RWSLB->mex || $RWSLB->bex) {
		if ($RWSLB->mok) {
			if ($RWSLB->perr)
				RWSSWarn("3003"); 
		} else if ($RWSLB->bok) {
			if ($RWSLB->perr)
				RWSSWarn("3003"); 
		} else { 
			RWSSWarn("3001");
		}
	} else { 
		RWSSWarn("3000");
	}
	RWSSStat("1004"); 
}
function RWSAAQList()
{
	global $DB;
	global $CFG;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("quizid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2067"); 
	$r_qzmi = intval($r_pm);
	$r_cmod = RWSCMUQuiz($r_qzmi);
	$r_cid = $r_cmod->course;
	RWSCMUCourse($r_cid, TRUE);
	$r_ql = RWSGSOpt("qlist");
	if ($r_ql === FALSE || strlen($r_ql) == 0)
		RWSSErr("2082"); 
	$r_qis = explode(",", $r_ql);
	if (count($r_qis) == 0 || strlen($r_qis[0]) == 0)
		RWSSErr("2082");
	foreach ($r_qis as $r_k=>$r_val) {
		if ($r_val === FALSE || strlen($r_val) == 0)
			RWSSErr("2108"); 
		$r_qis[$r_k] = intval($r_val);
	}
	$r_mr = $DB->get_record("modules",
	  array("id" => $r_cmod->module));
    if ($r_mr === FALSE) 
        RWSSErr("2043");
	$r_qiz = $DB->get_record($r_mr->name,
	  array("id" => $r_cmod->instance));
	if ($r_qiz === FALSE) 
        RWSSErr("2044");
	if (!isset($r_qiz->instance))
		$r_qiz->instance = $r_qiz->id; 
	$r_erri = array();
	foreach ($r_qis as $r_id) {
		$r_rc = $DB->get_record("question", array("id" => $r_id));
		$r_ok = ($r_rc !== FALSE);
		if ($r_ok) {
			if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
				quiz_add_quiz_question($r_id, $r_qiz);
			}
			else {
				$r_ok = quiz_add_quiz_question($r_id, $r_qiz);
			}
		}
		if (!$r_ok)
			$r_erri[] = $r_id;
	}
	if (count($r_erri) > 0) {
		$r_errl = implode(",", $r_erri);
		RWSSErr("2083,$r_errl");
	}
	if (count($r_erri) < count($r_qis))
		quiz_delete_previews($r_qiz);
	$r_qiz->grades = quiz_get_all_question_grades($r_qiz);
	$r_sumg = array_sum($r_qiz->grades);
	$DB->set_field("quiz", "sumgrades", $r_sumg, array("id" => $r_qiz->id));
	RWSSStat("1005"); 
}
function RWSAAQRand()
{
	global $DB;
    global $USER;
	global $CFG;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("quizid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2067"); 
	$r_qzmi = intval($r_pm);
	$r_cmod = RWSCMUQuiz($r_qzmi);
	$r_cid = $r_cmod->course;
	RWSCMUCourse($r_cid, TRUE);
	$r_mr = $DB->get_record("modules",
	  array("id" => $r_cmod->module));
	if ($r_mr === FALSE) 
		RWSSErr("2043");
	$r_qiz = $DB->get_record($r_mr->name,
	  array("id" => $r_cmod->instance));
	if ($r_qiz === FALSE) 
		RWSSErr("2044");
	$r_pm = RWSGSOpt("qcatid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2064"); 
	$r_qci = intval($r_pm);
	$r_qca = $DB->get_record("question_categories", array("id" => $r_qci));
	if ($r_qca === FALSE) 
		RWSSErr("2065");
	$r_ctx = get_context_instance_by_id($r_qca->contextid);
	$r_qcci = RWSGCFCat($r_ctx);
	if ($r_qcci != $r_cid) {
		if (is_siteadmin()) {
			if ($r_qcci != SITEID) {
				RWSSErr("2109");
			}
		}
		else {
			RWSSErr("2084");
		}
	}
	$r_pm = RWSGSOpt("qcount");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2085"); 
	$r_qct = intval($r_pm);
	if ($r_qct <= 0)
		RWSSErr("2085");
	$r_pm = RWSGSOpt("qgrade");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2086"); 
	$r_qg = round(floatval($r_pm));
	if ($r_qg <= 0)
		RWSSErr("2086");
	$r_mr = $DB->get_record("modules",
	  array("id" => $r_cmod->module));
    if ($r_mr === FALSE) 
        RWSSErr("2043");
	$r_qiz = $DB->get_record($r_mr->name,
	  array("id" => $r_cmod->instance));
	if ($r_qiz === FALSE) 
        RWSSErr("2044");
	if (!isset($r_qiz->instance))
		$r_qiz->instance = $r_qiz->id; 
	$r_aerr = 0;
	for ($r_i = 0; $r_i < $r_qct; $r_i++) {
		$r_qst = new stdClass();
		$r_qst->qtype = RWSRND;
		$r_qst->parent = 0;
		$r_qst->hidden = 0;
		$r_qst->length = 1;
		$r_qst->questiontext = 1; 
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
			$r_rqt = question_bank::get_qtype("random");
			$r_qst->name = $r_rqt->question_name($r_qca,
			  !empty($r_qst->questiontext));
		}
		else {
			$r_qst->name = random_qtype::question_name($r_qca,
			  !empty($r_qst->questiontext));
		}
		$r_qst->questiontextformat = FORMAT_HTML;
		$r_qst->penalty = 0;
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) 
			$r_qst->defaultmark = $r_qg;
		else
			$r_qst->defaultgrade = $r_qg;
		$r_qst->generalfeedback = "";
		$r_qst->generalfeedbackformat = FORMAT_HTML;
		$r_qst->category = $r_qca->id;
		$r_qst->stamp = make_unique_id_code();
		$r_qst->createdby = $USER->id;
		$r_qst->modifiedby = $USER->id;
		$r_qst->timecreated = time();
		$r_qst->timemodified = time();
		$r_qst->id = $DB->insert_record("question", $r_qst);
		$DB->set_field("question", "parent", $r_qst->id,
		  array("id" => $r_qst->id));
		$r_h = question_hash($r_qst);
		$DB->set_field("question", "version", $r_h,
		  array("id" => $r_qst->id));
		if (RWSFCmp($CFG->version, 2011070100, 2) >= 0) { 
			quiz_add_quiz_question($r_qst->id, $r_qiz);
		}
		else {
			$r_ok = quiz_add_quiz_question($r_qst->id, $r_qiz);
			if (!$r_ok) {
				$DB->delete_records("question", array("id" => $r_qst->id));
				$r_aerr++;
			}
		}
	}
	if ($r_aerr > 0) {
		RWSSErr("2087,$r_aerr");
	}
	if ($r_aerr < $r_qct)
		quiz_delete_previews($r_qiz);
	$r_qiz->grades = quiz_get_all_question_grades($r_qiz);
	$r_sumg = array_sum($r_qiz->grades);
	$DB->set_field("quiz", "sumgrades", $r_sumg, array("id" => $r_qiz->id));
	RWSSStat("1006"); 
}
function RWSAIQData()
{
	global $DB;
	global $USER;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("qcatid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2064"); 
	$r_qci = intval($r_pm);
	$r_qca = $DB->get_record("question_categories", array("id" => $r_qci));
	if ($r_qca === FALSE) 
		RWSSErr("2065");
	$r_ctx = get_context_instance_by_id($r_qca->contextid);
	$r_cid = RWSGCFCat($r_ctx);
	RWSCMUCourse($r_cid);
	$r_qfl = RWSGSOpt("qfile");
	if ($r_qfl === FALSE) {
		$r_qn = RWSGSOpt("qname");
		$r_qd = RWSGSOpt("qdata");
		$r_ecd = TRUE;
	}
	else {
		$r_qn = $r_qfl->filename;
		$r_qd = $r_qfl->filedata;
		$r_ecd = FALSE;
	}
	if ($r_qn === FALSE || strlen($r_qn) == 0)
		RWSSErr("2088"); 
	$r_qn = clean_filename($r_qn);
	if ($r_qd === FALSE || strlen($r_qd) == 0)
		RWSSErr("2089"); 
	RWSATLog($r_cid, "publish", "qcatid=$r_qci");
	$r_drp = 0;
	$r_ba = 0;
	$r_qis = RWSIQues(
	  $r_cid, $r_qci, $r_qn, $r_qd, $r_ecd, $r_drp, $r_ba);
	$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_ctxi = $r_ctx->id;
	$r_cmp = "mod_respondusws";
	$r_far = "upload";
	$r_iti = $USER->id;
	try {
		$r_fs = get_file_storage();
		if (!$r_fs->is_area_empty($r_ctxi, $r_cmp, $r_far, $r_iti, FALSE))	{
			$r_fls = $r_fs->get_area_files($r_ctxi, $r_cmp, $r_far, $r_iti);
			foreach ($r_fls as $r_fl) {
				$r_old = time() - 60*60*24*1; 
				if ($r_fl->get_timecreated() < $r_old)
					$r_fl->delete();
			}
		}
	} catch (Exception $r_e) {
		RWSSErr("2114");
	}
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<importqdata>\r\n";
	echo "\t<category_id>";
	echo utf8_encode(htmlspecialchars(trim($r_qci)));
	echo "</category_id>\r\n";
	echo "\t<dropped>";
	echo utf8_encode(htmlspecialchars(trim($r_drp)));
	echo "</dropped>\r\n";
	echo "\t<badatts>";
	echo utf8_encode(htmlspecialchars(trim($r_ba)));
	echo "</badatts>\r\n";
	$r_ql = implode(",", $r_qis);
	echo "\t<qlist>";
	echo utf8_encode(htmlspecialchars(trim($r_ql)));
	echo "</qlist>\r\n";
	echo "</importqdata>\r\n";
	exit;
}
function RWSAGQuiz()
{
	global $CFG;
	global $DB;
	global $RWSLB;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_fmt = RWSGSOpt("format");
	if (strcasecmp($r_fmt, "base64") == 0)
		$r_w64 = TRUE;
	else if (strcasecmp($r_fmt, "binary") == 0)
		$r_w64 = FALSE;
	else
		RWSSErr("2051"); 
	$r_pm = RWSGSOpt("quizid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2067"); 
	$r_qzmi = intval($r_pm);
	$r_cmod = RWSCMUQuiz($r_qzmi);
	$r_cid = $r_cmod->course;
	$r_crs = RWSCMUCourse($r_cid, TRUE);
	$r_mr = $DB->get_record("modules",
	  array("id" => $r_cmod->module));
    if ($r_mr === FALSE) 
        RWSSErr("2043");
	$r_qiz = $DB->get_record($r_mr->name,
	  array("id" => $r_cmod->instance));
	if ($r_qiz === FALSE) 
        RWSSErr("2044");
	$r_sec = $DB->get_record("course_sections",
	  array("id" => $r_cmod->section));
	if ($r_sec === FALSE) {
        RWSSErr("2079");
	}
    $r_qiz->coursemodule = $r_cmod->id;
    $r_qiz->section = $r_sec->section;
    $r_qiz->visible = $r_cmod->visible;
    $r_qiz->cmidnumber = $r_cmod->idnumber;
    $r_qiz->groupmode = groups_get_activity_groupmode($r_cmod);
    $r_qiz->groupingid = $r_cmod->groupingid;
    $r_qiz->groupmembersonly = $r_cmod->groupmembersonly;
    $r_qiz->course = $r_cid;
    $r_qiz->module = $r_mr->id;
    $r_qiz->modulename = $r_mr->name;
    $r_qiz->instance = $r_cmod->instance;
	if (RWSFCmp($CFG->version, 2011120500.00, 2) >= 0) 
		$r_qiz->showdescription = $r_cmod->showdescription;
	$r_cpl = new completion_info($r_crs);
	if ($r_cpl->is_enabled()) {
		$r_qiz->completion = $r_cmod->completion;
		$r_qiz->completionview = $r_cmod->completionview;
		$r_qiz->completionexpected = $r_cmod->completionexpected;
		$r_qiz->completionusegrade =
		  is_null($r_cmod->completiongradeitemnumber) ? 0 : 1;
	}
	if ($CFG->enableavailability) {
		$r_qiz->availablefrom = $r_cmod->availablefrom;
		$r_qiz->availableuntil = $r_cmod->availableuntil;
		if ($r_qiz->availableuntil) { 
			$r_qiz->availableuntil = strtotime("23:59:59",
			  $r_qiz->availableuntil);
		}
		$r_qiz->showavailability = $r_cmod->showavailability;
	}
	$r_its = grade_item::fetch_all(array('itemtype'=>'mod',
	  'itemmodule'=>$r_qiz->modulename, 'iteminstance'=>$r_qiz->instance,
	  'courseid'=>$r_cid));
	if ($r_its) {
        foreach ($r_its as $r_it) {
            if (!empty($r_it->outcomeid))
                $r_qiz->{'outcome_'.$r_it->outcomeid} = 1;
        }
        $r_gc = false;
        foreach ($r_its as $r_it) {
            if ($r_gc === false) {
                $r_gc = $r_it->categoryid;
                continue;
            }
            if ($r_gc != $r_it->categoryid) { 
                $r_gc = false;
                break;
            }
        }
        if ($r_gc !== false) 
            $r_qiz->gradecat = $r_gc;
    }
	$r_sfl = "";
	$r_sd = RWSEQSet($r_qiz, $r_sfl, $r_w64);
	if ($r_w64)
	{
		RWSRHXml();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
		echo "<getquiz>\r\n";
		echo "\t<name>";
		echo utf8_encode(htmlspecialchars(trim($r_qiz->name)));
		echo "</name>\r\n";
		echo "\t<id>";
		echo utf8_encode(htmlspecialchars(trim($r_qzmi)));
		echo "</id>\r\n";
		echo "\t<section_id>";
		echo utf8_encode(htmlspecialchars(trim($r_qiz->section)));
		echo "</section_id>\r\n";
		echo "\t<writable>yes</writable>\r\n";
		echo "\t<sfile>";
		echo utf8_encode(htmlspecialchars(trim($r_sfl)));
		echo "</sfile>\r\n";
		echo "\t<sdata>";
		echo utf8_encode(htmlspecialchars(trim($r_sd)));
		echo "</sdata>\r\n";
		if ($RWSLB->mex || $RWSLB->bex) {
			if ($RWSLB->mok) {
				if ($RWSLB->gerr) 
					echo "\t<service_warning>3002</service_warning>\r\n";
			} else if ($RWSLB->bok) {
				if ($RWSLB->gerr) 
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
		$r_fld = "name=\"" . htmlspecialchars(trim($r_qiz->name)) . "\"; ";
		$r_chdr = $r_fld;
		$r_fld = "id=" . htmlspecialchars(trim($r_qzmi)) . "; ";
		$r_chdr .= $r_fld;
		$r_fld = "section_id=" . htmlspecialchars(trim($r_qiz->section)) . "; ";
		$r_chdr .= $r_fld;
		$r_fld = "writable=yes";
		$r_chdr .= $r_fld;
		if ($RWSLB->mex || $RWSLB->bex) {
			if ($RWSLB->mok) {
				if ($RWSLB->gerr) {
					$r_fld = "; service_warning=3002";
					$r_chdr .= $r_fld;
				}
			} else if ($RWSLB->bok) {
				if ($RWSLB->gerr) {
					$r_fld = "; service_warning=3002";
					$r_chdr .= $r_fld;
				}
			} else { 
				$r_fld = "; service_warning=3001";
				$r_chdr .= $r_fld;
			}
		} else { 
			$r_fld = "; service_warning=3000";
			$r_chdr .= $r_fld;
		}
		header("X-GetQuiz: " . $r_chdr);
		RWSRHBin($r_sfl, strlen($r_sd));
		echo $r_sd;
	}
	exit;
}
function RWSAEQData()
{
	global $DB;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_fmt = RWSGSOpt("format");
	if (strcasecmp($r_fmt, "base64") == 0)
		$r_w64 = TRUE;
	else if (strcasecmp($r_fmt, "binary") == 0)
		$r_w64 = FALSE;
	else
		RWSSErr("2051"); 
	$r_qzmi = FALSE;
	$r_pm = RWSGSOpt("quizid");
	if ($r_pm !== FALSE && strlen($r_pm) > 0)
		$r_qzmi = intval($r_pm);
	$r_qci = FALSE;
	$r_pm = RWSGSOpt("qcatid");
	if ($r_pm !== FALSE && strlen($r_pm) > 0)
		$r_qci = intval($r_pm);
	if ($r_qzmi === FALSE && $r_qci === FALSE) {
		RWSSErr("2090");
	}
	else if ($r_qzmi !== FALSE && $r_qci === FALSE) {
		$r_cmod = RWSCMUQuiz($r_qzmi);
		$r_cid = $r_cmod->course;
	}
	else if ($r_qzmi === FALSE && $r_qci !== FALSE) {
		$r_qca = $DB->get_record("question_categories",
		  array("id" => $r_qci));
		if ($r_qca === FALSE) 
			RWSSErr("2065");
		$r_ctx = get_context_instance_by_id($r_qca->contextid);
		$r_cid = RWSGCFCat($r_ctx);
	}
	else 
	{
		RWSSErr("2091");
	}
	RWSCMUCourse($r_cid);
	if ($r_qzmi !== FALSE)
		RWSATLog($r_cid, "retrieve", "quizid=$r_qzmi");
	else 
		RWSATLog($r_cid, "retrieve", "qcatid=$r_qci");
	$r_qfl = "";
	$r_drp = 0;
	$r_ran = 0;
	if ($r_qzmi !== FALSE) {
		$r_qd = RWSEQQues(
		  $r_qzmi, $r_qfl, $r_drp, $r_ran, $r_w64);
	}
	else { 
		$r_qd = RWSEQCQues(
		  $r_qci, $r_qfl, $r_drp, $r_w64);
	}
	if ($r_w64)
	{
		RWSRHXml();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
		echo "<exportqdata>\r\n";
		if ($r_qzmi !== FALSE) {
			echo "\t<quiz_id>";
			echo utf8_encode(htmlspecialchars(trim($r_qzmi)));
			echo "</quiz_id>\r\n";
		}
		else 
		{
			echo "\t<category_id>";
			echo utf8_encode(htmlspecialchars(trim($r_qci)));
			echo "</category_id>\r\n";
		}
		echo "\t<dropped>";
		echo utf8_encode(htmlspecialchars(trim($r_drp)));
		echo "</dropped>\r\n";
		if ($r_qzmi !== FALSE)	{
			echo "\t<random>";
			echo utf8_encode(htmlspecialchars(trim($r_ran)));
			echo "</random>\r\n";
		}
		echo "\t<qfile>";
		echo utf8_encode(htmlspecialchars(trim($r_qfl)));
		echo "</qfile>\r\n";
		echo "\t<qdata>";
		echo utf8_encode(htmlspecialchars(trim($r_qd)));
		echo "</qdata>\r\n";
		echo "</exportqdata>\r\n";
	}
	else 
	{
		if ($r_qzmi !== FALSE)
			$r_fld = "quiz_id=" . htmlspecialchars(trim($r_qzmi)) . "; ";
		else 
			$r_fld = "category_id=" . htmlspecialchars(trim($r_qci)) . "; ";
		$r_chdr = $r_fld;
		$r_fld = "dropped=" . htmlspecialchars(trim($r_drp));
		$r_chdr .= $r_fld;
		if ($r_qzmi !== FALSE) {
			$r_fld = "; random=" . htmlspecialchars(trim($r_ran));
			$r_chdr .= $r_fld;
		}
		header("X-ExportQData: " . $r_chdr);
		RWSRHBin($r_qfl, strlen($r_qd));
		echo $r_qd;
	}
	exit;
}
function RWSAUFile()
{
	global $CFG;
	global $USER;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2057"); 
	if (strcasecmp($r_pm, "site") == 0)
		$r_cid = SITEID;
	else
		$r_cid = intval($r_pm);
	RWSCMUCourse($r_cid);
	$r_ff = RWSGSOpt("folder");
	if ($r_ff === FALSE || strlen($r_ff) == 0)
		RWSSErr("2092"); 
	$r_ff = clean_filename($r_ff);
	$r_fbn = RWSGSOpt("filebinary");
	if ($r_fbn === FALSE) {
		$r_fn = RWSGSOpt("filename");
		$r_fdat = RWSGSOpt("filedata");
		$r_ecd = TRUE;
	}
	else {
		$r_fn = $r_fbn->filename;
		$r_fdat = $r_fbn->filedata;
		$r_ecd = FALSE;
	}
	if ($r_fn === FALSE || strlen($r_fn) == 0)
		RWSSErr("2093"); 
	$r_fn = clean_filename($r_fn);
	if ($r_fdat === FALSE || strlen($r_fdat) == 0)
		RWSSErr("2094"); 
	if ($r_ecd) {
		$r_dcd_data = base64_decode($r_fdat);
		if ($r_dcd_data === FALSE) {
			RWSSErr("2097");
		}
	}
	else { 
		$r_dcd_data = $r_fdat;
	}
	$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
	$r_ctxi = $r_ctx->id;
	$r_cmp = "mod_respondusws";
	$r_far = "upload";
	$r_iti = $USER->id;
	$r_fpt = "/$r_ff/";
	$r_fna = $r_fn;
	$r_finf = array(
	  "contextid" => $r_ctxi, "component" => $r_cmp,
	  "filearea" => $r_far, "itemid" => $r_iti,
	  "filepath" => $r_fpt, "filename" => $r_fna
	  );
	$r_crpth = "$r_ff/$r_fn";
	try {
		$r_fs = get_file_storage();
		$r_fex = $r_fs->file_exists(
		  $r_ctxi, $r_cmp, $r_far, $r_iti, $r_fpt, $r_fna
		  );
		if ($r_fex) {
			RWSSErr("2096,$r_crpth");
		}
		if (!$r_fs->create_file_from_string($r_finf, $r_dcd_data))
			RWSSErr("2098"); 
	} catch (Exception $r_e) {
		RWSSErr("2098"); 
	}
	RWSRHXml();
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<uploadfile>\r\n";
	echo "\t<course_subpath>";
	echo utf8_encode(htmlspecialchars(trim($r_crpth)));
	echo "</course_subpath>\r\n";
	echo "</uploadfile>\r\n";
	exit;
}
function RWSADFile()
{
	global $CFG;
	global $USER;
	RWSCMAuth();
	RWSCMUSvc();
	RWSCMMaint();
	$r_pm = RWSGSOpt("courseid");
	if ($r_pm === FALSE || strlen($r_pm) == 0)
		RWSSErr("2057"); 
	if (strcasecmp($r_pm, "site") == 0)
		$r_cid = SITEID;
	else
		$r_cid = intval($r_pm);
	$r_crs = RWSCMUCourse($r_cid);
	$r_fmt = RWSGSOpt("format");
	if (strcasecmp($r_fmt, "base64") == 0)
		$r_w64 = TRUE;
	else if (strcasecmp($r_fmt, "binary") == 0)
		$r_w64 = FALSE;
	else
		RWSSErr("2051"); 
	$r_fr = RWSGSOpt("fileref");
	if ($r_fr === FALSE || strlen($r_fr) == 0)
		RWSSErr("2099"); 
	$r_st = stripos($r_fr, "/pluginfile.php");
	if ($r_st !== FALSE) {
		$r_st = strpos($r_fr, "/", $r_st+1);
		if ($r_st === FALSE)
			RWSSErr("2100"); 
		$r_pth = substr($r_fr, $r_st);
		$r_pts = explode("/", ltrim($r_pth, '/'));
		if (count($r_pts) < 5)
			RWSSErr("2100"); 
		$r_ctxi = intval(array_shift($r_pts));
		$r_cmp = clean_param(array_shift($r_pts), PARAM_SAFEDIR);
		$r_far = clean_param(array_shift($r_pts), PARAM_SAFEDIR);
		$r_iti = intval(array_shift($r_pts));
		$r_fna = clean_filename(array_pop($r_pts));
		$r_fpt = "/";
		if (count($r_pts) > 0)
			$r_fpt = "/". implode("/", $r_pts) . "/";
		try {
			$r_fs = get_file_storage();
			$r_fex = $r_fs->file_exists(
			  $r_ctxi, $r_cmp, $r_far, $r_iti, $r_fpt, $r_fna
			  );
			if (!$r_fex)
				RWSSErr("2100"); 
			$r_fl = $r_fs->get_file(
			  $r_ctxi, $r_cmp, $r_far, $r_iti, $r_fpt, $r_fna
			  );
			if ($r_fl === FALSE)
				RWSSErr("2101"); 
			$r_fdat = $r_fl->get_content();
			$r_fn = $r_fna;
		} catch (Exception $r_e) {
			RWSSErr("2101"); 
		}
	} else {
		$r_st = stripos($r_fr, "/draftfile.php");
		if ($r_st !== FALSE) {
			$r_st = strpos($r_fr, "/", $r_st+1);
			if ($r_st === FALSE)
				RWSSErr("2100"); 
			$r_pth = substr($r_fr, $r_st);
			$r_pts = explode("/", ltrim($r_pth, '/'));
			if (count($r_pts) < 5)
				RWSSErr("2100"); 
			$r_ctxi = intval(array_shift($r_pts));
			$r_ctx = get_context_instance_by_id($r_ctxi);
			if ($r_ctx->contextlevel != CONTEXT_USER)
				RWSSErr("2100"); 
			$r_cmp = array_shift($r_pts);
			if ($r_cmp !== "user")
				RWSSErr("2100"); 
			$r_far = array_shift($r_pts);
			if ($r_far !== "draft")
				RWSSErr("2100"); 
			$r_drf = intval(array_shift($r_pts));
			$r_rlp = implode("/", $r_pts);
			$r_fna = array_pop($r_pts);
			$r_fph = "/$r_ctxi/user/draft/$r_drf/$r_rlp";
			try {
				$r_fs = get_file_storage();
				$r_fl = $r_fs->get_file_by_hash(sha1($r_fph));
				if ($r_fl === FALSE)
					RWSSErr("2101"); 
				if ($r_fl->get_filename() == ".")
					RWSSErr("2101"); 
				$r_fdat = $r_fl->get_content();
				$r_fn = $r_fna;
			} catch (Exception $r_e) {
				RWSSErr("2101"); 
			}
		} else {
			$r_st = stripos($r_fr, "/file.php");
			if ($r_st !== FALSE) {
				$r_st = strpos($r_fr, "/", $r_st+1);
				if ($r_st === FALSE)
					RWSSErr("2100"); 
				$r_pth = substr($r_fr, $r_st);
				$r_pts = explode("/", ltrim($r_pth, '/'));
				if (count($r_pts) < 1)
					RWSSErr("2100"); 
				if ($r_crs->legacyfiles != 2)
					RWSSErr("2113"); 
				$r_ci = intval(array_shift($r_pts));
				if ($r_ci != $r_cid)
					RWSSErr("2100"); 
				$r_ctx = get_context_instance(CONTEXT_COURSE, $r_cid);
				$r_ctxi = $r_ctx->id;
				$r_rlp = implode("/", $r_pts);
				$r_fna = array_pop($r_pts);
				$r_fph = "/$r_ctxi/course/legacy/0/$r_rlp";
				try {
					$r_fs = get_file_storage();
					$r_fl = $r_fs->get_file_by_hash(sha1($r_fph));
					if ($r_fl === FALSE)
						RWSSErr("2101"); 
					$r_fdat = $r_fl->get_content();
					$r_fn = $r_fna;
				} catch (Exception $r_e) {
					RWSSErr("2101"); 
				}
			} else {
				RWSSErr("2100"); 
			}
		}
	}
	if ($r_w64)
	{
		RWSRHXml();
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
		echo "<dnloadfile>\r\n";
		echo "\t<filename>";
		echo utf8_encode(htmlspecialchars(trim($r_fn)));
		echo "</filename>\r\n";
		$r_ed = base64_encode($r_fdat);
		echo "\t<filedata>";
		echo utf8_encode(htmlspecialchars(trim($r_ed)));
		echo "</filedata>\r\n";
		echo "</dnloadfile>\r\n";
	}
	else 
	{
		RWSRHBin($r_fn, strlen($r_fdat));
		echo $r_fdat;
	}
	exit;
}
function RWSELog($r_msg)
{
}
function RWSEHdlr($r_ex)
{
	abort_all_db_transactions();
	$r_inf = get_exception_info($r_ex);
	RWSSErr("2112,$r_inf->errorcode");
}

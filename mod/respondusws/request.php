<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
$r_slf = dirname(__FILE__) . "/servicelib.php";
if (is_readable($r_slf)) {
    include_once($r_slf);
	defined("MOODLE_INTERNAL") || die();
}
else { 
	header("Content-Type: text/xml");
	echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n";
	echo "<service_error>2000</service_error>\r\n";
	exit;
}
raise_memory_limit(MEMORY_EXTRA);
set_exception_handler("RWSEHdlr");
RWSCMBVer();
RWSCMVer();
RWSCMInst();
if ($RWSECAS)
	RWSPCReqs();
$r_ac = RWSGSOpt("action");
if ($r_ac === FALSE || strlen($r_ac) == 0)
	RWSSErr("2001"); 
else
	RWSDSAct($r_ac);

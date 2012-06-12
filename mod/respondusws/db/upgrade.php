<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
defined("MOODLE_INTERNAL") || die();
function xmldb_respondusws_upgrade($oldversion = 0)
{
    global $DB;
	$dbman = $DB->get_manager();
	if ($oldversion < 2009073000) { 
	}
	if ($oldversion < 2009093000) { 
	}
	if ($oldversion < 2010042801) { 
	}
	if ($oldversion < 2010063001) { 
	}
	if ($oldversion < 2010063002) { 
	}
	if ($oldversion < 2010063003) { 
	}
	if ($oldversion < 2010063004) { 
	}
	if ($oldversion < 2010063005) { 
	}
	if ($oldversion < 2010063006) { 
	}
	if ($oldversion < 2011020100) { 
	}
	if ($oldversion < 2011040400) { 
	}
	if ($oldversion < 2011071500) { 
	}
	if ($oldversion < 2011080100) { 
	}
	if ($oldversion < 2011102500) { 
	}
	if ($oldversion < 2011121500) { 
	}
    return true;
}

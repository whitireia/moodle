<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
defined("MOODLE_INTERNAL") || die();
class backup_respondusws_activity_structure_step extends backup_activity_structure_step {
    protected function define_structure() {
        $respondusws = new backup_nested_element(
		  "respondusws", array("id"), array(
		  "course", "name", "intro", "introformat", "timecreated",
		  "timemodified"
		  ));
        $respondusws->set_source_table("respondusws",
		  array("id" => backup::VAR_ACTIVITYID));
        $respondusws->annotate_files("mod_respondusws", "intro", null);
        return $this->prepare_activity_structure($respondusws);
    }
}

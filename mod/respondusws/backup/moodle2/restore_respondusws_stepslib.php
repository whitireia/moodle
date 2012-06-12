<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
defined("MOODLE_INTERNAL") || die();
class restore_respondusws_activity_structure_step extends restore_activity_structure_step {
    protected function define_structure() {
        $paths = array();
        $paths[] = new restore_path_element("respondusws", "/activity/respondusws");
        return $this->prepare_activity_structure($paths);
    }
    protected function process_respondusws($data) {
        global $DB;
        $data = (object)$data;
        $oldid = $data->id;
        $data->course = $this->get_courseid();
        $data->timecreated = $this->apply_date_offset($data->timecreated);
        $data->timemodified = $this->apply_date_offset($data->timemodified);
        $newitemid = $DB->insert_record("respondusws", $data);
        $this->apply_activity_instance($newitemid);
    }
    protected function after_execute() {
        $this->add_related_files("mod_respondusws", "intro", null);
    }
}

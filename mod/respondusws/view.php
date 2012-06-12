<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
require_once(dirname(dirname(dirname(__FILE__))) . "/config.php");
require_once(dirname(__FILE__) . "/lib.php");
defined("MOODLE_INTERNAL") || die();
$id = optional_param("id", 0, PARAM_INT);
$a = optional_param("a", 0, PARAM_INT);
$dbman = $DB->get_manager();
if ($id) {
    $cm = get_coursemodule_from_id("respondusws", $id);
	if (!$cm)
        print_error("invalidcoursemodule");
    $course = $DB->get_record("course", array("id" => $cm->course));
	if ($course === false)
        print_error("coursemisconf");
	if ($dbman->table_exists("respondusws"))
		$module = $DB->get_record("respondusws", array("id" => $cm->instance));
	else
		$module = false;
	if ($module === false)
        print_error("invalidcminstance", "respondusws");
} else if ($a) {
	if ($dbman->table_exists("respondusws"))
		$module = $DB->get_record("respondusws", array("id" => $a));
	else
		$module = false;
	if ($module === false)
        print_error("invalidcminstance", "respondusws");
	$course = $DB->get_record("course", array("id" => $module->course));
	if ($course === false)
        print_error("coursemisconf");
    $cm = get_coursemodule_from_instance(
	  "respondusws", $module->id, $course->id);
	if ($cm === false)
        print_error("invalidcoursemodule");
} else {
    print_error("invalidcminstance", "respondusws");
}
$PAGE->set_url("/mod/respondusws/view.php", array("id" => $cm->id));
require_login($course, true, $cm);
$context = get_context_instance(CONTEXT_MODULE, $cm->id);
$PAGE->set_context($context);
if ($id) {
	add_to_log($course->id, "respondusws", "view", "view.php?id=$cm->id", "$module->id", $cm->id);
} else {
	add_to_log($course->id, "respondusws", "view", "view.php?a=$module->id", "$module->id");
}
$strmodule = get_string("modulename", "respondusws");
$renderer_file = dirname(__FILE__) . "/renderer.php";
if (is_readable($renderer_file)) 
	$output = $PAGE->get_renderer("mod_respondusws");
else
	$output = $OUTPUT;
$PAGE->set_title($strmodule);
$PAGE->set_heading($course->fullname);
echo $output->header();
$module->intro = trim($module->intro);
if (!empty($module->intro)) {
    echo $output->box(format_module_intro("respondusws", $module, $cm->id),
	  "generalbox", "intro");
}
else
	echo $output->box("No module instance data currently available");
echo $output->footer();

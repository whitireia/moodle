<?php
///////////////////////////////////////////////////////////////////////////////
// Respondus 4.0 Web Service Extension For Moodle
// Copyright (c) 2009-2011 Respondus, Inc.  All Rights Reserved.
// Date: December 19, 2011
require_once(dirname(dirname(dirname(__FILE__))) . "/config.php");
require_once("$CFG->dirroot/course/lib.php");
require_once(dirname(__FILE__) . "/lib.php");
defined("MOODLE_INTERNAL") || die();
$id = required_param("id", PARAM_INT);
$course = $DB->get_record("course", array("id" => $id));
if ($course === false)
    print_error("invalidcourseid");
$PAGE->set_url("/mod/respondusws/index.php", array("id" => $id));
require_course_login($course);
$dbman = $DB->get_manager();
if ($dbman->table_exists("respondusws"))
	$instances = $DB->get_records("respondusws", array("course" => $id), "id");
else
	$instances = array();
if (count($instances) == 0)
	print_error("notinstalled", "respondusws");
$PAGE->set_pagelayout("incourse");
add_to_log($course->id, "respondusws", "view all", "index.php?id=$course->id");
$strmodules = get_string("modulenameplural", "respondusws");
$strsectionname = get_string("sectionname", "format_" . $course->format);
$strname = get_string("name");
$strintro = get_string("moduleintro");
$strlastmodified = get_string("lastmodified");
$renderer_file = dirname(__FILE__) . "/renderer.php";
if (is_readable($renderer_file)) 
	$output = $PAGE->get_renderer("mod_respondusws");
else
	$output = $OUTPUT;
$PAGE->set_title($strmodules);
$PAGE->set_heading($course->fullname);
$PAGE->navbar->add($strmodules);
echo $output->header();
$modules = get_all_instances_in_course("respondusws", $course);
if (!$modules) {
    print_error("noinstances", "respondusws",
	  "$CFG->dirroot/course/view.php?id=$course->id");
}
$usesections = course_format_uses_sections($course->format);
if ($usesections)
	$sections = get_all_sections($course->id);
$table = new html_table();
$table->attributes["class"] = "generaltable_mod_index";
if ($usesections) {
	$table->head = array($strsectionname, $strname, $strintro);
    $table->align = array("center", "left", "left");
} else {
    $table->head = array($strlastmodified, $strname, $strintro);
    $table->align = array("left", "left", "left");
}
$modinfo = get_fast_modinfo($course);
$currentsection = "";
foreach ($modules as $module) {
	$cm = $modinfo->cms[$module->coursemodule];
    if ($usesections) {
        $printsection = "";
        if ($module->section !== $currentsection) {
            if ($module->section) {
                $printsection = get_section_name($course,
				  $sections[$module->section]);
			}
            if ($currentsection !== "")
                $table->data[] = "hr";
            $currentsection = $module->section;
        }
    } else {
        $printsection = "<span class=\"smallinfo\">"
		              . userdate($module->timemodified)
					  . "</span>";
    }
    $class = "";
    if (!$module->visible) 
		$class = "class=\"dimmed\"";
    $table->data[] = array(
        $printsection,
        "<a $class href=\"view.php?id=$cm->id\">"
		. format_string($module->name)
		. "</a>",
        format_module_intro("respondusws", $module, $cm->id)
		);
}
echo html_writer::table($table);
echo $output->footer();

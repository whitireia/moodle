<?php // $Id: preview.php,v 1.13 2011/06/21 16:00:14 mchurch Exp $

/// This page displays a non-completable instance of questionnaire

    require_once("../../config.php");
    require_once($CFG->dirroot.'/mod/questionnaire/lib.php');

    $id     = optional_param('id', 0, PARAM_INT);
    $sid    = optional_param('sid', 0, PARAM_INT);
    $popup  = optional_param('popup', 0, PARAM_INT);
    $qid    = optional_param('qid', 0, PARAM_INT);

    if ($id) {
        if (! $cm = get_coursemodule_from_id('questionnaire', $id)) {
            print_error('invalidcoursemodule');
        }

        if (! $course = $DB->get_record("course", array("id" => $cm->course))) {
            print_error('coursemisconf');
        }

        if (! $questionnaire = $DB->get_record("questionnaire", array("id" => $cm->instance))) {
            print_error('invalidcoursemodule');
        }
    } else {
        if (! $survey = $DB->get_record("questionnaire_survey", array("id" => $sid))) {
            print_error('surveynotexists', 'questionnaire');
        }
        if (! $course = $DB->get_record("course", array("id" => $survey->owner))) {
            print_error('coursemisconf');
        }
        /// Dummy questionnaire object:
        $questionnaire = new Object();
        $questionnaire->id = 0;
        $questionnaire->course = $course->id;
        $questionnaire->name = $survey->title;
        $questionnaire->sid = $sid;
        $questionnaire->resume = 0;
        ///Dummy cm object:
        if (!empty($qid)) {
            $cm = get_coursemodule_from_instance('questionnaire', $qid, $course->id);
        } else {
            $cm = false;
        }
    }

/// Check login and get context.
    require_login($course->id, false, $cm);
    $context = $cm ? get_context_instance(CONTEXT_MODULE, $cm->id) : false;

	$url = new moodle_url('/mod/questionnaire/preview.php');
    if ($id !== 0) {
        $url->param('id', $id);
    }
    if ($sid) {
        $url->param('sid', $sid);
    }
    $PAGE->set_url($url);

    if (!$popup) {
        $PAGE->set_context($context);
    }

    $questionnaire = new questionnaire($qid, $questionnaire, $course, $cm);
    $owner = (trim($questionnaire->survey->owner) == trim($course->id));

    $canpreview = (!isset($questionnaire->capabilities) &&
                   has_capability('mod/questionnaire:manage', get_context_instance(CONTEXT_COURSE, $course->id))) ||
                  (isset($questionnaire->capabilities) && $questionnaire->capabilities->editquestions && $owner);
    if (!$canpreview) {
        /// Should never happen, unless called directly by a snoop...
        print_error('nopermissions', 'questionnaire', $CFG->wwwroot.'/mod/questionnaire/view.php?id='.$cm->id);
    }

    $SESSION->questionnaire->current_tab = 'preview';

    $qp = get_string('preview_questionnaire', 'questionnaire');
    $pq = get_string('previewing', 'questionnaire');

/// Print the page header
    if (!$popup) {
        $navigation = build_navigation($pq, $cm);
    } else {
        $navigation = '';
        $PAGE->set_pagelayout('popup');
    }
    $PAGE->set_title(format_string($qp));
    if (!$popup) {
        $PAGE->set_heading(format_string($course->fullname));
        $PAGE->navbar->add($pq);
    }
    echo $OUTPUT->header();

    if (!$popup) {
        include('tabs.php');
    }
    $questionnaire->survey_print_render('', '', $course->id);
    if ($popup) {
        echo $OUTPUT->close_window_button();
    }
    echo $OUTPUT->footer($course);
?>
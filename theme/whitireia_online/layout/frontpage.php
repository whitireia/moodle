<?php
$hasheading = ($PAGE->heading);
$hasnavbar = (empty($PAGE->layout_options['nonavbar']) && $PAGE->has_navbar());
$hasfooter = (empty($PAGE->layout_options['nofooter']));
$hassidepre = $PAGE->blocks->region_has_content('side-pre', $OUTPUT);
$hassidepost = $PAGE->blocks->region_has_content('side-post', $OUTPUT);
$showsidepre = $hassidepre && !$PAGE->blocks->region_completely_docked('side-pre', $OUTPUT);
$showsidepost = $hassidepost && !$PAGE->blocks->region_completely_docked('side-post', $OUTPUT);

$custommenu = $OUTPUT->custom_menu();
$hascustommenu = (empty($PAGE->layout_options['nocustommenu']) && !empty($custommenu));


$bodyclasses = array();
if ($showsidepre && !$showsidepost) {
    $bodyclasses[] = 'side-pre-only';
} else if ($showsidepost && !$showsidepre) {
    $bodyclasses[] = 'side-post-only';
} else if (!$showsidepost && !$showsidepre) {
    $bodyclasses[] = 'content-only';
}
if ($hascustommenu) {
    $bodyclasses[] = 'has_custom_menu';
}

if ($hascustommenu) {
    $bodyclasses[] = 'has_navbar';
}

echo $OUTPUT->doctype() ?>
<html <?php echo $OUTPUT->htmlattributes() ?>>
<head>
    <title><?php echo $PAGE->title ?></title>
    <link rel="shortcut icon" href="<?php echo $OUTPUT->pix_url('favicon', 'theme')?>" />
    <?php echo $OUTPUT->standard_head_html() ?>
</head>
<body id="<?php p($PAGE->bodyid) ?>" class="<?php p($PAGE->bodyclasses.' '.join(' ', $bodyclasses)) ?>">
<?php echo $OUTPUT->standard_top_of_body_html() ?>

<div id="page">
	<div id="wrapper">
	
<!-- start OF header -->
		<div id="page-header" class="page-header-home">
			
				<div id="header-profileblock" class="header-profileblock">
		
		 <?php if (isloggedin()) {
		
		echo html_writer::tag('div', $OUTPUT->user_picture($USER, array('size'=>100)), array('class'=>'userimg'));
		 ?>
		 
		  <div class="userleft">
		 <div class="larger">
		 <?php
		 $myname = fullname($USER, true);
		  echo html_writer::link(new moodle_url('/user/profile.php', array('id'=>$USER->id)), $myname).' ';
		 ?>
		 </div>
		 <div class="psmaller">
		  <?php echo html_writer::link(new moodle_url('/user/edit.php', array('id'=>$USER->id)), 'edit profile').' ';
		 ?>
		 &nbsp;&nbsp;&nbsp;<a href="<?php echo $CFG->wwwroot ?>/my/">my home</a>&nbsp;&nbsp;&nbsp;
		 <a href="<?php echo $CFG->wwwroot ?>/login/logout.php">logout</a>
		 
		 
		 </div>
		 </div>
		 
		 
		 <?php
		 } else {
		 ?>
		 
		 <img src="<?php echo $OUTPUT->pix_url('user1', 'theme'); ?>" class="userimg" />
		 
		 <div class="userleft">
		 <div class="larger"><a href="<?php echo $CFG->wwwroot ?>/login/index.php">You are not logged in</a></div>
		 <div class="psmaller"><a href="<?php echo $CFG->wwwroot ?>/login/index.php">LOGIN</a></div>
		 </div>
		 
		 
		 <?php
		 }
		 ?>
		
		
		
		</div>
				
				
		</div>
<!-- end of header -->		

<!-- start of custom menu -->	
<?php if ($hascustommenu) { ?>
<div id="menuwrap">
<a href="<?php echo $CFG->wwwroot ?>"><img src="<?php echo $OUTPUT->pix_url('home_icon', 'theme'); ?>" id="homeimg" /></a>
<div id="custommenu"><?php echo $custommenu; ?></div>

<div id="datetime"><?php echo strftime("%A %d %B %Y"); ?></div>
</div>
<?php } ?>
<!-- end of menu -->

<div id="page-content-wrapper">
<!-- start OF moodle CONTENT -->
 <div id="page-content">
        <div id="region-main-box">
            <div id="region-post-box">
            
                <div id="region-main-wrap">
                    <div id="region-main">
                        <div class="region-content">
                        
                        <?php //include('frontlinks.php')?>
                          
                            <?php echo core_renderer::MAIN_CONTENT_TOKEN ?>
                        </div>
                    </div>
                </div>
                
                <?php if ($hassidepre) { ?>
                <div id="region-pre" class="block-region">
                    <div class="region-content">
                        <?php echo $OUTPUT->blocks_for_region('side-pre') ?>
                    </div>
                </div>
                <?php } ?>
                
                <?php if ($hassidepost) { ?>
                <div id="region-post" class="block-region">
                    <div class="region-content">
                        <?php echo $OUTPUT->blocks_for_region('side-post') ?>
                    </div>
                </div>
                <?php } ?>
                
            </div>
        </div>
    </div>
<!-- end OF moodle CONTENT -->
<div class="clearer"></div>
</div>
<!-- end OF moodle CONTENT wrapper -->


<!-- start of footer -->	
<div id="page-footer">
<?php
echo $OUTPUT->login_info();
//echo $OUTPUT->home_link();
echo $OUTPUT->standard_footer_html();
?>
</div>
<!-- end of footer -->	



	</div><!-- end #wrapper -->
</div><!-- end #page -->	

<?php echo $OUTPUT->standard_end_of_body_html() ?>
</body>
</html>
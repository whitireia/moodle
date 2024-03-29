//  $Id: lib.js,v 1.11 2011/10/06 00:55:38 gb2048 Exp $

/**
 * Collapsed Topics Information
 *
 * @package    course/format
 * @subpackage topcoll
 * @copyright  2009-2011 @ G J Barnard.
 * @link       http://docs.moodle.org/en/Collapsed_Topics_course_format
 * @license    http://creativecommons.org/licenses/by-sa/3.0/ Creative Commons Attribution-ShareAlike 3.0 Unported (CC BY-SA 3.0)
 */

// Global variables 
var toggleBinaryGlobal = "10000000000000000000000000000000000000000000000000000"; // 53 possible toggles - current settings in Moodle for number of topics - 52 + 1 for topic 0.  Need 1 as Most Significant bit to allow toggle 1+ to be off.
var thesparezeros = "00000000000000000000000000"; // A constant of 26 0's to be used to pad the storage state of the toggles when converting between base 2 and 36, this is because cookies need to be compact.
var thewwwroot;  // For the toggle graphic and extra files.
var thecookiesubid; // For the cookie sub name.
var numToggles = 0;
var cookieExpires;
var ie7OrLess = false;
var ie = false;

// Because I like the idea of private and public methods, public will have an underscore in the name.

// Initialise with the information supplied from the course format 'format.php' so we can operate.
// Args - wwwroot is the URL of the Moodle site, moodleid is the site short name (courseid 0) and courseid is the id of the current course to allow for settings for each course.
function topcoll_init(wwwroot, moodleid, courseid, cookielifetime)
{
    // Init.
    thewwwroot = wwwroot;
    thecookiesubid = moodleid + courseid;
    cookieExpires = cookielifetime; // null indicates that it is a session cookie.

    if (/MSIE (\d+\.\d+);/.test(navigator.userAgent))
    {
        // Info from: http://www.javascriptkit.com/javatutors/navigator.shtml - accessed 2nd September 2011.
        var ieversion = new Number(RegExp.$1);
        ie = true;
        //alert('Is IE ' + ieversion);
        if (ieversion <= 7)
        {
            //alert('Is IE 7');
            ie7OrLess = true;
        }
    }
}

function set_number_of_toggles(atoggle)
{
    numToggles = atoggle;
}

// Change the toggle binary global state as a toggle has been changed - toggle number 0 should never be switched as it is the most significant bit and represents the non-toggling topic 0.
// Args - toggleNum is an integer and toggleVal is a string which will either be "1" or "0"
function togglebinary(toggleNum, toggleVal)
{
    // Toggle num should be between 1 and 52 - see definition of toggleBinaryGlobal above.
    if ((toggleNum >=1) && (toggleNum <= 52))
    {
        //alert("togglebinary tbg:" + toggleBinaryGlobal);
        
        // Safe to use.
        var start = toggleBinaryGlobal.substring(0,toggleNum);
        var end = toggleBinaryGlobal.substring(toggleNum+1);
        //var newval = start + toggleVal + end;
        toggleBinaryGlobal = start + toggleVal + end;
        
        //toggleBinaryGlobal = newval;

        //alert("togglebinary toggleNum:" + toggleNum + " st:" + start + " ed:" + end + " tv:" + toggleVal + " tbg:" + toggleBinaryGlobal);

        save_toggles();
    }
}

// Toggle functions
// Args - target is the table row element in the DOM to be toggled.
//        image is the img tag element in the DOM to be changed.
//        toggleNum is the toggle number to change.
//        reloading is a boolean that states if the function is called from reload_toggles() so that we do not have to resave what we already know - ohh for default argument values.
function toggleexacttopic(target,image,toggleNum,reloading)  // Toggle the target tr and change the image which is the a tag within the td of the tr above target
{
    if(document.getElementById)
    {
        if (ie == true)
        {
            var displaySetting = "block"; // IE is always different from the rest!
        }
        else
        {
            var displaySetting = "table-row";
        }
        
        //alert("toggleexacttopic tdisp:" + target.style.display + " disp:" + displaySetting + " ton:" + toggleNum + " rl:" + reloading);

        if (target.style.display == displaySetting)
        {
            target.style.display = "none";
            if (ie7OrLess == true)
            {
                target.className += " collapsed_topic";  //add the class name
                //alert('Added class name');
            }
            image.style.backgroundImage = "url(" + thewwwroot + "/course/format/topcoll/arrow_down.png)";
            // Save the toggle!
            if (reloading == false)    togglebinary(toggleNum,"0");
        }
        else
        {
            target.style.display = displaySetting;
            if (ie7OrLess == true)
            {
                target.className = target.className.replace(/\b collapsed_topic\b/,'') //remove the class name
                //alert('Removed class name');
            }
            image.style.backgroundImage = "url(" + thewwwroot + "/course/format/topcoll/arrow_up.png)";
            // Save the toggle!
            if (reloading == false) togglebinary(toggleNum,"1");
        }
    }
}

// Called by the html code created by format.php on the actual course page.
// Args - toggler the tag that initiated the call, toggleNum the number of the toggle for which toggler is a part of - see format.php.
function toggle_topic(toggler,toggleNum)
{
   if(document.getElementById)
    {
        imageSwitch = toggler;
        targetElement = toggler.parentNode.parentNode.nextSibling; // Called from a <td>  or <div> inside a <tr> or <li> so find the next <tr> or <li>.

        toggleexacttopic(targetElement,imageSwitch,toggleNum,false);
    }
}

// Current maximum number of topics is 52, but as the converstion utilises integers which are 32 bit signed, this must be broken into two string segments for the
// process to work.  Therefore each 6 character base 36 string will represent 26 characters for part 1 and 27 for part 2 in base 2.
// This is all required to save cookie space, so instead of using 53 bytes (characters) per course, only 12 are used.
// Convert from a base 36 string to a base 2 string - effectively a private function.
// Args - thirtysix - a 12 character string representing a base 36 number.
function to2baseString(thirtysix)
{
    // Break apart the string because integers are signed 32 bit and therefore can only store 31 bits, therefore a 53 bit number will cause overflow / carry with loss of resolution.
    var firstpart = parseInt(thirtysix.substring(0,6),36);
    var secondpart = parseInt(thirtysix.substring(6,12),36);
    var fps = firstpart.toString(2);
    var sps = secondpart.toString(2);
    
    // Add in preceding 0's if base 2 sub strings are not long enough
    if (fps.length < 26)
    {
        // Need to PAD.
        fps = thesparezeros.substring(0,(26 - fps.length)) + fps;
    }
    if (sps.length < 27)
    {
        // Need to PAD.
        sps = thesparezeros.substring(0,(27 - sps.length)) + sps;
    }
    
    return fps + sps;
}

// Convert from a base 2 string to a base 36 string - effectively a private function.
// Args - two - a 52 character string representing a base 2 number.
function to36baseString(two)
{
    // Break apart the string because integers are signed 32 bit and therefore can only store 31 bits, therefore a 52 bit number will cause overflow / carry with loss of resolution.
    var firstpart = parseInt(two.substring(0,26),2);
    var secondpart = parseInt(two.substring(26,53),2);
    var fps = firstpart.toString(36);
    var sps = secondpart.toString(36);

    // Add in preceding 0's if base 36 sub strings are not long enough
    if (fps.length < 6)
    {
        // Need to PAD.
        fps = thesparezeros.substring(0,(6 - fps.length)) + fps;
    }
    if (sps.length < 6)
    {
        // Need to PAD.
        sps = thesparezeros.substring(0,(6 - sps.length)) + sps;
    }

    return fps + sps;
}

// Cookie Monster
// Args - value to save to the cookie
function savetopcollcookie(value)
{
    //create a YUI instance and use the cookie module. 
    if (cookieExpires == null)
    {
        // Session Cookie...
        YUI().use('cookie', function(Y){ 
           Y.Cookie.setSub("mdl_cf_topcoll",thecookiesubid,value); 
           //alert("Bongo After " + thecookiesubid + " " + value);
        });
    // Using Sub cookies, so, name, moodleid/courseid, value.
        // This is not a Moodle table but in fact the cookies name.
    }
    else
    {
        // Expiring Cookie...
        YUI().use('cookie', function(Y){ 
            var newDate = new Date();
            newDate.setTime(newDate.getTime() + cookieExpires); 
            Y.Cookie.setSub("mdl_cf_topcoll",thecookiesubid,value, { expires: newDate }); 
            //alert("Bongo After " + thecookiesubid + " " + value + " " + newDate + " " + cookieExpires);
        });
        // This is not a Moodle table but in fact the cookies name.
    }
}

// Get the cookie - yum.
function restoretopcollcookie(daYUI)
{
    return daYUI.Cookie.getSub("mdl_cf_topcoll",thecookiesubid); 
}

// 'Private' version of reload_toggles
function reloadToggles()
{
    YUI().use('cookie', function(daYUI){ 
        // Get the cookie if there!
        //var storedval = restoretopcollcookie(daYUI);
        var storedval = daYUI.Cookie.getSub("mdl_cf_topcoll",thecookiesubid);
        if (storedval != null)
        {
            toggleBinaryGlobal = to2baseString(storedval);
        }
        //alert("Bongo3 " + thecookiesubid + " " + storedval + " " + numToggles + " " + toggleBinaryGlobal);
    
        for (var theToggle = 1; theToggle <= numToggles; theToggle++)
        {
            if ((theToggle <= numToggles) && (toggleBinaryGlobal.charAt(theToggle) == "1")) // Array index 0 is never tested - MSB thing.
            {
                toggleexacttopic(document.getElementById("section-"+theToggle),document.getElementById("sectionatag-" + theToggle),theToggle,true);
                //alert("Bongo4 " + thecookiesubid + " " + theToggle);
            }
        }    
    });
}

// Toggle persistence functions
// Reload the toggles - called from an onload event handler setup at the bottom of format.php
// aToggle sets the number of toggles we have on this course so that when restoring the state we do not attempt to set something that
// no longer exists.  This can happen when the number of sections is reduced and we return to the course and reload the page
// using the data from the cookie.
function reload_toggles(aToggle)
{
    numToggles = aToggle;
    
    YUI().use('node-base', function(daYUI) {
     daYUI.on("domready", reloadToggles);
    });
}

// Show a specific topic - used when in 'Show topic x' mode.
function show_topic(theTopic)
{
    toggleexacttopic(document.getElementById("section-"+theTopic),document.getElementById("sectionatag-" + theTopic),theTopic,true);
    //alert("show_topic " + theTopic);
}

// Save the toggles - called from togglebinary and an the unload event handler at the bottom of format.php which does not work for a refresh even though it should!
function save_toggles()
{
    savetopcollcookie(to36baseString(toggleBinaryGlobal));
}

// Functions that turn on or off all toggles.
// Alter the state of the toggles.  Where 'state' needs to be true for open and false for close.
function allToggle(state)
{
    var target;
    var displaySetting;

    if (state == false)
    {
         // All on to set off!
        if (ie == true)
        {
            displaySetting = "block"; // IE is always different from the rest!
        }
        else
        {
            displaySetting = "table-row";
        }
    }
    else
    {
        // Set all off to set on.
        displaySetting = "none";
    }

    for (var theToggle = 1; theToggle <= numToggles; theToggle++)
    {
        target = document.getElementById("section-"+theToggle);
        target.style.display = displaySetting;
        toggleexacttopic(target,document.getElementById("sectionatag-" + theToggle),theToggle,false);
    }
}

// Open all toggles.
function all_opened()
{
    allToggle(true);
}

// Close all toggles.
function all_closed()
{
    allToggle(false);
}
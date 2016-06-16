#!c:\Strawberry\perl\bin\perl.exe
#### #### #### #### #### #### #### #### #### #### #### #### #### #### #### ####
####  Author: Don Turnblade
#### Purpose: Asset an Agent Office System for MPCI Compliance
#### Control: State Farm HackDay ownership using Open Source Licensing
####
#### Plan:
#### 1) Process Core Health Check Tests using Powershell
#### 2) Build Remote Trusts for PowerShell use on a test system
#### 3) Modify Test System to match a Sample Agent Office Configuration
####
#### Dependencies:
#### 1) Standard State Farm Windows End Point Configuration
####    A) Powershell, winrm service turned on
####    B) Trusted Credentials on both systems
####    C) Common Domain or Workgroup Trust between systems
####    D) Common DNS support 
#### 
#### #### #### #### #### #### #### #### #### #### #### #### #### #### #### ####
#YYYYDDMM Who Ver Why
#20160615 DWT 0.0 Proof of Concept Powershell reg query commands
#20160615 DWT 0.1 Shell Script
#20160615 DWT 0.2 Registry Date Converter
#
$ws = "PowerShell_Tests.pl" ;
$ps = 'c:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe' ;
#
use Time::Local ;
#
#### Symantec End Point Security Tests:
#
### Client is Running
#
$health_state = 0 ;
$run_state = 0 ;
$reg_query = 'reg query \'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Filesystem\RealTimeScan\' /v OnOff' ;
$ps_cmd = "$ps -command $reg_query" ;
if(!open(CMD, "$ps_cmd |")) {
	printf("#### %s Error: could not run command: %s\n", $ws, $ps_cmd) ;
	exit 1 ;
}
while(<CMD>) {
  if(/0x1/) {
    $run_state++ ;
	#print "Run State: $run_state Key: $_" ;
  }
}
close(CMD) ;
#
$net_cmd = "net start" ;
$ps_cmd = "$ps -command $net_cmd" ;
if(!open(CMD, "$ps_cmd |&")) {
	printf("#### %s Error: could not run command: %s\n", $ws, $ps_cmd) ;
	exit 1 ;
}
while(<CMD>) {
    if(/Symantec Endpoint Protection/i) {
		$run_state++ ;	
		#print "Run State: $run_state Process: $_" ;
	}
}
close(CMD) ;
if($run_state > 1) {
  printf("Antivirus is running...\n") ;
  $health_state++ ;
} else {
  printf("Check if Antivirus is running...\n") ;
}
#
### Current Client Version
#
$run_state = 0 ;
@good_version = (12,1,6318,6100) ;
$reg_query = 'reg query \'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SMC\' /v ProductVersion' ;
$ps_cmd = "$ps -command $reg_query" ;
if(!open(CMD, "$ps_cmd |")) {
	printf("#### %s Error: could not run command: %s\n", $ws, $ps_cmd) ;
	exit 1 ;
}
while(<CMD>) {
  #print $_ ;
  if(/ProductVersion\s+REG_SZ\s+([0-9\.]+)(\s*$)/) {
	$av_version = $1 ;  # get the filed with numbers and periods in it.
	@sub_version = split(/\./, $av_version) ;
	if($#sub_version == $#good_version) {
		for($i=0; $i<=$#sub_version; $i++) {
			if($sub_version[$i] >= $good_version[$i]) {
					$run_state++ ;
			}
		}
		if($run_state == ($#good_version + 1)) {
			$health_state++ ;
           	printf("Antivirus Version %s is good...\n", $av_version) ;	  
		}
	} else {
	  printf("Double Check Antivirus Version...\n") ;
	  printf("\tReference Version %s\n", join(/\./, @good_version)) ;
	  printf("\tDetected Version %s\n", $av_version) ;
	}
	#print "Version: $av_version\n" ;
  }
}
close(CMD) ;
#
### Recent Antivirus Update
#
$run_state = 0 ;
$good_age = 30 ;   # Days or less
$timenow = time ;
@stampnow = localtime ;
$now_year = $stampnow[5] + 1900 ;
$now_month = $stampnow[4] + 1 ;
$now_day = $stampnow[3] ;
$timethen = $timenow - $good_age * 24 * 3600 ;
@stampthen = localtime($timethen) ;
$then_year = $stampthen[5] + 1900 ;
$then_month = $stampthen[4] + 1 ;
$then_day = $stampthen[3] ;
#print "Now: $timenow  Stampnow: @stampnow  ($now_year, $now_month, $now_day)\n" ;
#print "Checking for signatures older then Than: $then_month/$then_day/$then_year\n" ;
#
#### Get date, move back a few days, convert in to registry comparison form.
#
@good_version = (12,1,6318,6100) ;
#
### Get Symantec date
#
$reg_query = 'reg query \'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\' /v PatternFileDate' ;
$ps_cmd = "$ps -command $reg_query" ;
if(!open(CMD, "$ps_cmd |")) {
	printf("#### %s Error: could not run command: %s\n", $ws, $ps_cmd) ;
	exit 1 ;
}
while(<CMD>) {
  #print $_ ;
  if(/PatternFileDate\s+REG_BINARY\s+([0-9A-Fa-f]+)(\s*$)/) {
	$av_date = $1 ;  # Hexidecimal Time Stamp
	#print "AV_File_Date: $av_date\n" ;
	@signature_date = @{Symantec_Date_Stamp($av_date)} ;
	$testtime = timelocal(0,0,0,($signature_date[2]), ($signature_date[1] - 1), ($signature_date[0]-1900)) ;
	#print "AV Signature Date: @signature_date\n" ;
	#print "Test Time: $testtime\n" ;
	@testcheck = localtime($testtime) ;
	#printf("Year: %s Month %s, Day %s\n",$testcheck[5]+1900,$testcheck[4]+1,$testcheck[3]) ;
    if(($testtime >= $timethen) and ($testtime <= $timenow)) {
		$health_state++ ;
		printf("Antivirus Signature %s/%s/%s is good...\n", $testcheck[4]+1,$testcheck[3],$testcheck[5]+1900) ;
	} else {
		printf("Antivirus Signature is out of date: %s/%s/%s\n", $testcheck[4]+1,$testcheck[3], $testcheck[5]+1900) ;
	}
	#@sub_version = split(/\./, $av_version) ;
	#if($#sub_version == $#good_version) {
	#	for($i=0; $i<=$#sub_version; $i++) {
	#		if($sub_version[$i] >= $good_version[$i]) {
	#				$run_state++ ;
	#		}
	#	}
	#	if($run_state == ($#good_version + 1)) {
	#		$health_state++ ;
    #      	printf("Antivirus Version %s is good...\n", $av_version) ;	  
	#	}
	#} else {
	#  printf("Double Check Antivirus Version...\n") ;
	#  printf("\tReference Version %s\n", join(/\./, @good_version)) ;
	#  printf("\tDetected Version %s\n", $av_version) ;
	#}
	#print "Version: $av_version\n" ;
  }
}
close(CMD) ;
exit 0 ;


# Recently Updated
# Current Client Version 
@reg_queries = ('\'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\' /v PatternFileDate', '\'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\' /v TimeOfLastScan', '\'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Filesystem\RealTimeScan\' /v OnOff', '\'HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SMC\' /v ProductVersion') ;
#
foreach $reg_query (@reg_queries) {
	print "$ps -command reg query $reg_query\n" ;
	$result = system("$ps -command reg query $reg_query") ;
}
#print "$ps -command reg query $reg_queries[1]\n" ;
#$result = system("$ps -command reg query $reg_queries[1]") ;
#[‎6/‎10/‎2016 12:10 PM] Jarrod Haney: 
#reg query "HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV" /v PatternFileDate
#[Same scheme]
# Signature


#reg query "HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV" /v TimeOfLastScan
#[Same Scheme]
# Last Use

#reg query "HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\AV\Storages\Filesystem\RealTimeScan" /v OnOff
#[on/off]


#C:\Users\idm9>reg query "HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SMC" /v ProductVersion 
#[Client Product Version]

#Todays date:
#.2E050A0000000000 
#(2E)(05)(0A)
#(YY)(MM)(DD)
#(46 + 1970)(05+1)(10)
#(2016)(06)(10)  2016 June 10.
#### #### #### #### #### #### #### #### #### #### #### #### #### #### #### ####
#### Subroutines
#### #### #### #### #### #### #### #### #### #### #### #### #### #### #### ####
sub help($) {
	my $script = shift ;
	printf("\nUsage  %s  {Input_csv}\n", $script) ;
}
sub Symantec_Date_Stamp($) {
	my $hex_date = shift ;
	my @normal_date = () ;
	if($hex_date =~ /[^0-9A-Fa-f]+/) {
		printf("#### Symantec_Date_Stamp Error: could not read hexidecimal date %s\n", $hex_date) ;
		exit 1;
	}
	#
	$normal_date[0] = hex(substr($hex_date,0,2)) + 1970;  # Year Code  (Decimal + 1970)
	$normal_date[1] = hex(substr($hex_date,2,2)) + 1 ;  # Month Code (Decimal + 1)
	$normal_date[2] = hex(substr($hex_date,4,2)) ;  # Day Code   (Decimal)
	#print "$hex_date  @normal_date\n" ;
	return(\@normal_date) ;
}

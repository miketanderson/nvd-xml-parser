<?php
/*  XML parser for the NIST's National Vulnerability Database (NVD)
*   Open Source license, NCSA/U. of Illinois
*   Version 1.01, September 2, 2005
*   Pascal Meunier
*   Purdue University CERIAS
*   Contact: pmeunier 
*  
*   Version 1.02, January 2014
*   Mike Anderson
*
*  Uses the basic XML parser included with PHP
*  that doesn't perform schema validation
*   see http://us2.php.net/xml
*
*  The NVD's XML schema doesn't have conflicting name tags
*  at various nesting levels, so its parsing is relatively 
*  simple.  Therefore, a flat namespace (independent of nesting level)
*  works fine.  This simple approach doesn't work, for example, with Microsoft's
*  XML export of vulnerabilities.

*  Note that this parser does not have cases for all tags in the NVD schema.
*  Simply add "case" statements for the additional tags that matter to you.
*
*  The data from parsing needs further validation or escaping if it is 
*  to be inserted into another database.

*  -Replace the first line with the path to your installation of PHP
*  for command line execution.  Delete the path to PHP on the first line for 
*  execution with an Apache web server.
*  -Choose a source for the XML file (see below)

*ChangeLog:
* 1.0 first version August 29, 2005
* 1.01 September 2, 2005
   -Changed the name nvdcve-1999-2002.xml to nvdcve-2002.xml to match nvd changes
   -Removed comment "from Apache" regarding https locations, as they work from the command line too, depending on how PHP was installed
   -Now uses command line argument if present as XML source
   -Now captures the content of <REF> tags
*/

error_reporting (E_ALL);

$debug = false; // will print messages about every field found if true
$output = true;	//set to true to output to a csv format
$html_output = true; //set to true to enable html links & features
$count_entries = 0; // count number of new CVE entries found today

//print the csv header
if ($output) {
   print_header();
}

// Choose a source for parsing
// Check if a source was passed as argument
if (isset($argv[1])) {
   parse_this($argv[1]);
} else {
   //parse_this("nvdcve-2004.xml");
   // other possibilities:
   //parse_this("http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-recent.xml");
   //parse_this("http://nvd.nist.gov/download/nvdcve-2014.xml");
   parse_this("http://nvd.nist.gov/download/nvdcve-recent.xml");
   //
   // The following do not work with vanilla PHP installs 
   // without the wrapper "https" (e.g., MacOS X default install)
   //parse_this("https://nvd.nist.gov/download/nvdcve-2002.xml");
   //parse_this("https://nvd.nist.gov/download/nvdcve-2003.xml");
   //parse_this("https://nvd.nist.gov/download/nvdcve-2004.xml");
   //parse_this("https://nvd.nist.gov/download/nvdcve-2005.xml");
   //parse_this("https://nvd.nist.gov/download/nvdcve-2006.xml");
}

echo "Found $count_entries entries in this NVD location\n";
die; // not necessary, added for clarity

function startElement($parser, $name, $attrs) {
   global $all_data, $CVE, $debug, $output, $insert, $vendor, $vendors, $product, $products, $vers, $count_entries, $desc_type, $html_output, $vendor_array;
   if ($debug) {
      echo "processing tag named '$name'\n";
   }
   //
   // the switch statement should enumerate all of the possible name tags.
   // State is kept using global variables, so that nested tags can
   // access their context.
   //
   switch ($name) {
      case 'ENTRY':
         $count_entries++;
         // get name and publication date
         $CVE = validate_CVE($attrs['NAME']);
         $published = validate_date($attrs['PUBLISHED']);
	 $CVSS_score = '';
	 $severity = '';
	 $CVSS_base = '';
	 $custom_severity = '';
 	 if (isset($attrs['CVSS_SCORE'])) {
	     $CVSS_score = $attrs['CVSS_SCORE'];
	 }
 	 if (isset($attrs['SEVERITY'])) {
	     $severity = $attrs['SEVERITY'];
	 }
 	 if (isset($attrs['CVSS_BASE_SCORE'])) {
	     $CVSS_base = $attrs['CVSS_BASE_SCORE'];
         }
	//assign custom severity here
	//example:
	if (floatval($CVSS_base) > 4) {
		$custom_severity = 'HIGH';
	} else if (floatval($CVSS_base) > 3) { 
		$custom_severity = 'MEDIUM';
	} else {
		$custom_severity = 'LOW';
	}
	
	 $vendors = '';
     $products = '';
	 $versions = '';
         // other attributes, such as severity, are available
         // see http://nvd.nist.gov/download/nvdcve-xmldoc.cfm
         if ($debug) {
            echo "found CVE entry $CVE with publication date ". $attrs['PUBLISHED']."\n";
         }
	 if ($output) {
		if ($html_output) {
			echo "\"<a href = \"http://web.nvd.nist.gov/view/vuln/detail?vulnId=$CVE\">$CVE</a>\",";
		}
		else {
			echo "\"$CVE\",";
		}
		echo "\"$published\",\"$CVSS_score\",\"$severity\",\"$custom_severity\",";
   	 }
         break;
      case 'DESCRIPT':
         // if there ever was more than one type of description
         // remember which source with a global
         // NVD or CVE
         $desc_type = $attrs['SOURCE'];
         // reset data accumulator
         $all_data = '';
         // need to wait for end tag to get contents
	 //if ($output) {
	  //  echo "\"$desc_type\",";
	 //}
         break;
      case 'PROD':
         $vendor = $attrs['VENDOR'];
         $product = $attrs['NAME'];
		 $vendor_array = '';
		 $vers = '';
         if ($CVE == '') {
            echo "error, no CVE number";
            die;
         }
         if ($debug) {
            echo "found vendor $vendor";
            echo " found product $product\n";
         }
         if ($vendor == "") {
            // this happens
            echo "NVD integrity alert: no vendor for product $product, CVE is $CVE\n";
         }
         if ($product == "") {
            echo "NVD integrity alert: no product, CVE is $CVE\n";
         }
	 if ($output) {
 	    $vendor_array .= "$vendor - $product;";
	    //$products .= $product;
	    echo "\"$vendor\",\"$product\",";
	 }
         break;
      case 'LOSS_TYPES':
         break;
      case 'VULNS_TYPES':
         break;
      case 'REF':
         // source, url, etc...
         if ($debug) {
            echo " reference from ". $attrs['SOURCE'];
            echo " is available at ". $attrs['URL'];
            echo "\n";
         }
         $all_data = '';
         // need to wait for end tag to get contents
	 #if ($output) {
	 #  echo "\"" . $attrs['SOURCE'] . "\",\"" . $attrs['URL'] . "\",";
	 #}
         break;
      case 'VERS':
	     
	     if (isset($attrs['NUM'])) {
			$vers .= $attrs['NUM'];
		 }
		 if (isset($attrs['EDITION'])) {
			$vers .= ' ' . $attrs['EDITION'];
		 }
         if ($debug) {
            echo " version ". $attrs['NUM'];
            echo " of product $product is vulnerable\n";
         }
		 if ($output) {
			echo "\"$vers\",";
		 }
         break;
      case '':
         break;
   }
}

function endElement($parser, $name) {
   global $all_data, $CVE, $debug, $output, $desc_type, $vendor_array;
   switch ($name) {
      case 'ENTRY':
         $CVE = '';
	 if ($output) {
	    echo "<br>";
         }
         break;
      case 'DESCRIPT':
         if ($CVE == '') {
            echo "error, no CVE number";
            die;
         }
		 if ($desc_type != 'cve') {
			if ($debug) {
				echo "Found non CVE description, skipping\n";
			}
		 } else {
			if ($output) {
				echo "\"". validate_output($all_data) ."\",";
			}	 
		}
		 
         if ($debug) {
            echo "found description $all_data\n for CVE entry $CVE\n";
         }
	 
            
         // reset data accumulator
         $all_data = '';
         break;
      case 'REF':
         if ($debug) {
            echo "found reference content '$all_data'\n for CVE entry $CVE\n";
         }            
         // reset data accumulator
         $all_data = '';
         break;
      case 'AVAIL':
         if ($debug) {
            echo "loss type is availability\n";
         }
         break;
      case 'CONF':
         if ($debug) {
            echo "loss type is confidentiality\n";
         }
         break;
      case 'INT':
         if ($debug) {
            echo "loss type is integrity\n";
         }
         break;
      case 'SEC_PROT':
         if ($debug) {
            echo "loss type is security protection\n";
         }
         break;
      case 'ACCESS':
         if ($debug) {
            echo "vulnerability type is access\n";
         }
         break;
      case 'INPUT':
         if ($debug) {
            echo "vulnerability type is input\n";
         }
         break;
      case 'DESIGN':
         if ($debug) {
            echo "vulnerability type is design\n";
         }
         break;
      case 'EXCEPTION':
         if ($debug) {
            echo "vulnerability type is exception\n";
         }
         break;
      case 'ENV':
         if ($debug) {
            echo "vulnerability type is environment\n";
         }
         break;
      case 'CONFIG':
         if ($debug) {
            echo "vulnerability type is configuration\n";
         }
         break;
      case 'RACE':
         if ($debug) {
            echo "vulnerability type is race\n";
         }
         break;
      case 'OTHER':
         if ($debug) {
            echo "vulnerability type is other\n";
         }
         break;
      case 'REMOTE':
         if ($debug) {
            echo "vulnerability range is remote\n";
         }
         break;
      case 'LOCAL':
         if ($debug) {
            echo "vulnerability range is local\n";
         }
         break;
      case 'USER_INIT':
         if ($debug) {
            echo "vulnerability range is through a user\n";
         }
         break;
	  case 'VULN_SOFT':
	    if ($debug) {
		    echo "vulnerable software\n";
		}
		if ($output) {
			//not ready for go-live, turns out it is hard to show dynamically formed data in csv format
			//echo "\"$vendor_array\",";
		}
		$vendor_array = '';
		break;
      case '':
         break;
   }
}

function characterData($parser, $data) {
   global $all_data;
   // concatenate due to bug with & according to a user entry in PHP docs
   // entry by sam at cwa dot co dot nz, Sept 2000
   // This issue might have been fixed later.  The fix can't hurt though.
   $all_data .= $data;
   //echo $all_data;
}

function parse_this($url) {
   // code for this function is from http://us2.php.net/xml
   $xml_parser = xml_parser_create();
   // use case-folding so we are sure to find the tag in $map_array
   xml_parser_set_option($xml_parser, XML_OPTION_CASE_FOLDING, true);
   xml_set_element_handler($xml_parser, "startElement", "endElement");
   xml_set_character_data_handler($xml_parser, "characterData");
   if (!($fp = fopen($url, "r"))) {
      die("could not open XML input");
   }
   while ($data = fread($fp, 4096)) {
      if (!xml_parse($xml_parser, $data, feof($fp))) {
          die(sprintf("XML error: %s at line %d",
                      xml_error_string(xml_get_error_code($xml_parser)),
                      xml_get_current_line_number($xml_parser)));
      }
   }
   xml_parser_free($xml_parser);
}

function validate_CVE($input) {
   // expecting something like CAN-2004-0002
   // NVD documentation suggests this reg exp,
   // (http://nvd.nist.gov/download/nvdcve-xmldoc.cfm)
   // (CAN|CVE)-/d/d/d/d-/d/d/d/d
   // which doesn't work.  See below
   if (preg_match('/(CAN|CVE)-\d\d\d\d-\d\d\d\d/', $input, $matches)) {
      return $matches[0];
   } else {
      // if there was an error (false) or if 0 matches
      die ("Invalid CVE number encountered: $input"); 
   }
}

function validate_output($input) {
   // escapes anything with double quotes
   // to conform to csv standard
   // by converting double quotes to single
   if (preg_match('/"/', $input)) {
	return preg_replace('/\"/', '""', $input);
	} 
	return $input;
}

function validate_Date($input) {
   // expecting something like 2004-03-03
   if (preg_match('/\d\d\d\d-\d\d-\d\d/', $input, $matches)) {
      return $matches[0];
   } else {
      // if there was an error (false) or if 0 matches
      die ("Invalid date encountered: $input"); 
   }
}

function print_header() {
   echo "\"CVE\",\"Published Date\",\"CVSS Score\",\"CVE Severity\",\"Custom Severity\",\"Description\",\"Vendor - Product - Version\"<br>";
}
?> 

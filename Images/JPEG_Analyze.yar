
// TODO make these private


rule is_jpeg : JPEG
{
	meta:
		Description = "Identify file as JPEG image"
	strings:
		$magic = { ff d8 ff e? 00 }
	condition:
		$magic at 0
}


rule jfif_exists : JPEG
{
	meta:
		Description = "JPEG contains JFIF metadata (APP0)"
	strings:
		$jfif = { ff e0 [2] 4a 46 49 46}
	condition:
		is_jpeg and $jfif
}

rule exif_exists : JPEG
{
	meta:
		Description = "JPEG contains EXIF metadata (APP1)"
	strings:		
		$exif = { ff e1 ?? ?? 45 78 69 66 00 00  (49 49 | 4d 4d) }
		//$exif = { ff e1 ?? ?? 45 78 69 66 00 00  (49 49 | 4d 4d) 2A 00 08 00 00 00 }	// Depends if motorola or intel	
	condition:
		is_jpeg and $exif
}
		

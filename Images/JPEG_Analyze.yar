
// TODO make these private
rule is_jpeg
{
	meta:
		Description = "Identify file as JPEG image"
	strings:
		$magic = { ff d8 ff e? }
	condition:
		$magic at 0
}

// TODO: fix bug. doesn't really work
rule exif_exists 
{
	meta:
		Description = "JPEG contains EXIF metadata (APP1)"
	strings:
		$exif = { ff e1 ?? ?? 45 78 69 66 00 00 49 49 2A 00 08 00 00 00 }
	condition:
		is_jpeg and $exif
}
		

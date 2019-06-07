/* 
 * Check if image contains trailing byes
 * If there are any bytes after image ends
 */

 rule jpg_trailing_bytes
 {
	meta:
		description = "Find JPG files with trailing bytes"
		comment = "Checks last bytes are { ff d9 }"
	strings:
        $header = { ff d8 ff e? 00 10 4a 46 49 46 }
		$footer = { ff d9 }
	condition:
		($header at 0) and ((#footer != 1) or not ($footer at filesize - 2))
}

rule gif_trailing_bytes
{
	meta:
		description = "Find GIF files with traling bytes"
		comment = "Checks the last bytes are { 3b }"
		note = "bug, only checks the last byte. Doesn't check the first occurence"
	strings:
        $header = /^GIF8[79]a/
		$footer = { 3b }
	condition:
		($header at 0) and not ($footer at filesize -1)
}


rule bmp_trailing_bytes
{
	meta:
		description = "Find BMP files with traling bytes"
	strings:
		$header = "BM"
	condition:
		($header at 0) and 
		(uint32(uint32(0x02)) != filesize)  // Offset 0x02 : Image size (4 bytes)
}


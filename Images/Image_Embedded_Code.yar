/*
    Finds PHP code in JP(E)Gs, GIFs, PNGs, BMPs
    Magic numbers via Wikipedia.
*/

private rule is_image
{
	meta:
		description = "Checks if image format"
		author = "QoL15155"
    strings:
        $gif = /^GIF8[79]a/
        $jfif = { ff d8 ff e? 00 }
        $png = { 89 50 4e 47 0d 0a 1a 0a }
		$bmp = "BM"

    condition:
        (($gif at 0) or
        ($jfif at 0) or
        ($png at 0) or 
		($bmp at 0)) 
}


rule php_in_image : JPEG
{
    meta:
        author      = "Vlad https://github.com/vlad-s"
        date        = "2016/07/18"
        description = "Finds image files w/ PHP code in images"
	strings:
        $php_tag = "<?php" nocase
    condition:
		is_image and $php_tag
}


rule html_javascript_in_image : JPEG
{
	meta:
		author = "QoL15155"
		date = "2019/06/06"
		description = "Find image files with html or javascript code embedded"
	strings:
		$js_tag = "javascript" 
		$html_tag = "<html>" nocase
		$script_tag = /<script.*src.*<\/script>/ nocase
	condition:
		is_image and ($js_tag or $html_tag or $script_tag)
}

rule autorun_in_image : JPEG
{
	meta:
		author = "QoL15155"
		date = "2019/06/09"
		description = "Embedded autorun.inf inside image. Could be used by to execute malicious programs automatically"
		example = "4bdacdc5c7f9e04fe69b9bc6602847527dca2d6396b370acef31bda816dd6e8e"
	strings:
		$autorun = "[autorun]"
	condition:
		is_image and $autorun
		
}


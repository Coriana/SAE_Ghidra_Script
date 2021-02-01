/*
    This Yara ruleset is for quickly finding and naming short subs/funcs.
*/

rule Nullsub 
{
	meta:
		author = "_SAE_"
		description = "Nullsub"
		date = "2021-01"
	strings:
		$c0 = { cc cc c2 00 00 cc cc cc }
	condition:
		$c0
}

rule ReturnParam_1
{
	meta:
		author = "_SAE_"
		description = "Returns param 1"
		date = "2021-01"
	strings:
		$c0 = { cc cc 48 8b c1 c3 cc cc }
	condition:
		$c0
}
rule ReturnParam_2
{
	meta:
		author = "_SAE_"
		description = "Returns param 2"
		date = "2021-01"
	strings:
		$c0 = { cc cc 48 8b c2 c3 cc cc }
	condition:
		$c0
}

rule Return_0
{
	meta:
		author = "_SAE_"
		description = "Returns 0"
		date = "2021-01"
	strings:
		$c0 = { cc cc 32 c0 c3 cc cc }
	condition:
		$c0
}

rule Return_1
{
	meta:
		author = "_SAE_"
		description = "Returns 1"
		date = "2021-01"
	strings:
		$c0 = { cc cc b0 01 c3 cc cc }
	condition:
		$c0
}

/*
rule Thunk
{
	meta:
		author = "_SAE_"
		description = "Thunk Function"
		date = "2021-01"
	strings:
		$c0 = { cc cc e9 ?? ?? ?? ?? cc cc }
	condition:
		$c0
}
*/

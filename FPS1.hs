song 0 = ""
song n = song (n-1) ++ "\n" ++ verse n
printSong n = putStr (song n)
verse n = line1 n ++ line ++ line3 n ++ line
numbers = ["One","Two","Three","Four","Five","Six","Seven","Eight","Nine","Ten"]
line1 n 
	| n==1		= numbers!!(n-1) ++ " man went to mow\n"
	| otherwise	= numbers!!(n-1) ++ " men went to mow\n"
line = "Went to mow a meadow\n"
line3 n 
	| n==1 		= "One man and his dog"
	| otherwise	= numbers!!(n-1) ++ " men, " ++ map toLower (line3 (n-1))
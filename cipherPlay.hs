import Data.Char (ord, chr)

-- | charshift takes an ASCII character c and shifts it down the ASCII table by an integer x number of steps.
charshift x c = chr (mod (x + (ord c)) 128)

-- | Implements a simple shift cipher on ASCII strings.
shift x s = map (charshift x) s

-- | Inverse if shift.
unshift x s = shift (-x) s

-- | Find the mod m inverse of an integer x. Throws an error when x is not a unit mod m (i.e. when x is nilpotent).
modInverse x m 
	| mod m x == 0 = error "error: not a unit"
	| otherwise = fst (head (filter (\x -> (snd x) == 1) (zip [1..m] (map ((flip mod) m) (map (*x) [1..m])))))

-- | A single character multiplication cipher on ASCII characters. Throws an error when x is not a unit mod 128.
charMult x c
	| mod 128 x == 0 = error "error: not a unit mod 128"
	| otherwise = chr (mod (x * (ord c)) 128)

-- | Implement a single character affine cipher on ASCII characters.
charAffine a b c = charshift b (charMult a c)

-- | Inverse of charAffine
reverseCharAffine a b c = charMult (modInverse a 128) (charshift (-b) c)

-- | An affine cipher on ASCII strings.
affine a b s = map (charAffine a b) s

-- | Inverse of affine.
reverseAffine a b s = map (reverseCharAffine a b) s

-- | Implement a polyalphabetic affine cipher on ASCII strings.
polyAffine a b s = zipWith ($) (zipWith charAffine (cycle a) (cycle b)) s

-- | Inverse of polyAffine
reversePolyAffine a b s = zipWith ($) (zipWith reverseCharAffine (cycle a) (cycle b)) s

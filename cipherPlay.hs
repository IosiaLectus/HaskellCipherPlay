import Data.Char (ord, chr)

-- | Check if two integers are relatively prime
relPrime :: Int -> Int -> Bool
relPrime x y = gcd x y == 1

-- | charshift takes an ASCII character c and shifts it down the ASCII table by an integer x number of steps.
charshift :: Int -> Char -> Char
charshift x c = chr (mod (x + (ord c)) 128)

-- | Implements a simple shift cipher on ASCII strings.
shift :: Int -> [Char] -> [Char]
shift x s = map (charshift x) s

-- | Inverse of shift.
unshift :: Int -> [Char] -> [Char]
unshift x s = shift (-x) s

-- | Find the mod m inverse of an integer x. Throws an error when x is not a unit mod m (i.e. when x is nilpotent).
modInverse :: Int -> Int -> Int
modInverse x m 
	| not (relPrime x m) = error "error: not a unit"
	| otherwise = (fst.head.(filter p).(zip [1..m]).(map ((flip mod m).(*x)))) [1..m]
	where p =  (\x -> (snd x) == 1)

-- | A single character multiplication cipher on ASCII characters. Throws an error when x is not a unit mod 128.
charMult :: Int -> Char -> Char
charMult x c
	| not (relPrime 128 x) = error "error: not a unit mod 128"
	| otherwise = chr (mod (x * (ord c)) 128)

-- | Implement a single character affine cipher on ASCII characters.
charAffine :: Int -> Int -> Char -> Char
charAffine a b c = charshift b (charMult a c)

-- | Inverse of charAffine
reverseCharAffine :: Int -> Int -> Char -> Char
reverseCharAffine a b c = charMult (modInverse a 128) (charshift (-b) c)

-- | An affine cipher on ASCII strings.
affine :: Int -> Int -> [Char] -> [Char]
affine a b s = map (charAffine a b) s

-- | Inverse of affine.
reverseAffine :: Int -> Int -> [Char] -> [Char]
reverseAffine a b s = map (reverseCharAffine a b) s

-- | Implement a polyalphabetic affine cipher on ASCII strings.
polyAffine :: [Int] -> [Int] -> [Char] -> [Char]
polyAffine a b s = zipWith ($) (zipWith charAffine (cycle a) (cycle b)) s

-- | Inverse of polyAffine
reversePolyAffine :: [Int] -> [Int] -> [Char] -> [Char]
reversePolyAffine a b s = zipWith ($) (zipWith reverseCharAffine (cycle a) (cycle b)) s

-- | An implementation of the Blum Blum Shub cryptographic pseudo-random number generator. 
blumBlumShub :: Int -> Int -> Int -> Int
blumBlumShub x n k
	| k == 0 = mod (x^2) n
	| otherwise = blumBlumShub (x^2) n (k-1)


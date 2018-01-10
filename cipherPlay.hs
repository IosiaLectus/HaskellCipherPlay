import Data.Char (ord, chr)



-- | Arithmatic tools

first25Primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]

-- | Check if two integers are relatively prime
relPrime :: Int -> Int -> Bool
relPrime x y = gcd x y == 1

-- | Naive prime test
isPrime :: Int -> Bool
isPrime p
	| p < 2 = False
	| p < 100 = elem p first25Primes
	| otherwise = and (map (relPrime p) (filter (< n) (first25Primes ++ [101,103..p])))
	where n = floor (sqrt (fromIntegral p))

-- | Computes x^y mod n
modExp :: Int -> Int -> Int -> Int
modExp x y n
	| y < 0 = error "second argument must be a non-negative integer"
	| y == 0 = 1
	| otherwise = mod ((mod x n) * (modExp x (y-1) n)) n

-- | Checks if p is a fermat pseudoprime relative to base a
fermatPseudoPrime :: Int -> Int -> Bool
fermatPseudoPrime p a
	| a < 2 = error "second argument must be greater than 1"
	| (p-2) < a = error "second argument must be at least two less than first argument"
	| not (relPrime p a) = False
	| otherwise = (modExp a (p-1) p) == 1 

-- | Find the mod m inverse of an integer x. Throws an error when x is not a unit mod m (i.e. when x is nilpotent).
modInverse :: Int -> Int -> Int
modInverse x m 
	| not (relPrime x m) = error "error: not a unit"
	| otherwise = (fst.head.(filter p).(zip [1..m]).(map ((flip mod m).(*x)))) [1..m]
	where p =  (\x -> (snd x) == 1)

-- | Convert a list representing the digits of an integer in some base to an Int. Notice that the least signigicant digits should come first.
digitStringToInt :: Int -> [Int] -> Int
digitStringToInt base digits
	| null digits = 0
	| otherwise = (base * (digitStringToInt base (tail digits))) + (head digits)

-- | given a list, convert it to a list of lists of a given maximum length by grouping consecutive elements together
deflatten :: Int -> [a] -> [[a]]
deflatten n lst
	| n < 1 = error "First argument must be a strictly positive integer"
	| length lst <= n = [lst]
	| otherwise = (take n lst):(deflatten n (drop n lst))



-- | Affine ciphers

-- | charshift takes an ASCII character c and shifts it down the ASCII table by an integer x number of steps.
charshift :: Int -> Char -> Char
charshift x c = chr (mod (x + (ord c)) 128)

-- | Implements a simple shift cipher on ASCII strings.
shift :: Int -> [Char] -> [Char]
shift x s = map (charshift x) s

-- | Inverse of shift.
unshift :: Int -> [Char] -> [Char]
unshift x s = shift (-x) s

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



-- | Blum Blum Shub

-- | An implementation of the Blum Blum Shub cryptographic pseudo-random number generator. 
blumBlumShub :: Int -> Int -> Int -> Int -> ([Int],Int)
blumBlumShub x p q k
	| not ((mod p 4) == 3) = error "second and third arguments must be 3 (mod 4)"
	| not ((mod q 4) == 3) = error "second and third arguments must be 3 (mod 4)"
	| k < 1 = error "last argument must be strictly positive"
	| k == 1 = ((mod y 2):[], y)
	| otherwise = (((mod y 2):(fst bbs)), (snd bbs))
	where n = p*q
	      y = mod (x^2) n
	      bbs = blumBlumShub y p q (k-1)

-- | Use Blum Blum Shub to generate a list of random ints of some number of binary digits 
randomIntList :: Int -> Int -> Int -> Int -> Int -> ([Int],Int)
randomIntList x p q num digits = (ret,y)
	where bbs = blumBlumShub x p q (num*digits)
	      lst = deflatten digits (fst bbs)
	      ret = map (digitStringToInt 2) lst
	      y = snd bbs

-- | Use Blum Blum Shub to generate a random ASCII string 
bbsString :: Int -> Int -> Int -> Int -> ([Char],Int)
bbsString x p q k = ((map chr (fst tpl)),(snd tpl))
	where tpl = randomIntList x p q k 7

-- | Use Blum Blum Shub and a random seed to produce a pseudorandom key for a polyalphabetic shift cipher
bbsPadShift :: Int -> Int -> Int -> [Char] -> [Char]
bbsPadShift seed p q plaintxt = polyAffine (repeat 1) (fst (randomIntList seed p q (length plaintxt) 7)) plaintxt

-- | Use Blum Blum Shub and a random seed to produce a pseudorandom key for a polyalphabetic shift cipher
bbsPadUnshift :: Int -> Int -> Int -> [Char] -> [Char]
bbsPadUnshift seed p q plaintxt = reversePolyAffine (repeat 1) (fst (randomIntList seed p q (length plaintxt) 7)) plaintxt



-- | RSA

-- | Given primes p and q, generate an RSA key
rsaKeyGen :: Int -> Int -> Int -> (Int, Int)
rsaKeyGen p q e
	| not (isPrime p) = error "first two arguments must be prime"
	| not (isPrime q) = error "first two arguments must be prime"
	| not (relPrime e lam) = error "invalid third argument"
	| otherwise = (n,d)
	where n = p * q
	      lam = lcm (p-1) (q-1)
	      d = modInverse e lam

-- | encrypt with RSA
rsaEncrypt :: Int -> Int -> Int -> Int
rsaEncrypt n e m = modExp m e n
	      




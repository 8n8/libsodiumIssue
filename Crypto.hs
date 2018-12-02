{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto (sodiumInit, sign) where

import qualified Data.ByteString as B
import qualified Foreign as F
import qualified Foreign.C.Types as T
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.ByteString.Internal as Bi

crypto_sign_BYTES :: Int
crypto_sign_BYTES = 64

packCString :: Int -> F.Ptr F.Word8 -> IO B.ByteString
packCString len cstr = create len $ \p -> Bi.memcpy p cstr len

create :: Int -> (F.Ptr F.Word8 -> IO ()) -> IO B.ByteString
create l f = do
    fp <- Bi.mallocByteString l
    F.withForeignPtr fp f
    return $! Bi.PS fp 0 l

foreign import ccall unsafe "sodium.h crypto_sign_detached"
    c_crypto_sign_detached
        :: CUString
        -> F.Ptr T.CULLong
        -> CUString
        -> T.CULLong
        -> CUString
        -> IO T.CInt

sign :: B.ByteString -> B.ByteString -> Either Int B.ByteString
sign message secretKey =
  unsafePerformIO $
    useAsCString message $ \messagePtr ->
    useAsCString secretKey $ \secretKeyPtr ->
    F.allocaBytes crypto_sign_BYTES $ \sig -> do
      status <- c_crypto_sign_detached
                    sig
                    F.nullPtr
                    messagePtr
                    (fromIntegral $ B.length message)
                    secretKeyPtr
      case status of
        0 -> do
          packed <- packCString crypto_sign_BYTES $ F.castPtr sig
          return $ Right packed
        errCode -> return $ Left $ fromIntegral errCode

foreign import ccall unsafe "sodium.h sodium_init"
  c_sodium_init :: IO T.CInt

type CUString = F.Ptr T.CUChar

useAsCString :: B.ByteString -> (CUString -> IO a) -> IO a
useAsCString (Bi.PS fp o l) action =
 F.allocaBytes (l+1) $ \buf ->
   F.withForeignPtr fp $ \p -> do
     Bi.memcpy buf (p `F.plusPtr` o) (fromIntegral l)
     F.pokeByteOff buf l (0::F.Word8)
     action (F.castPtr buf)

sodiumInit :: IO Int
sodiumInit = fromIntegral <$> c_sodium_init

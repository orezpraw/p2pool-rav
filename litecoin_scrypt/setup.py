from distutils.core import setup, Extension

ltc_scrypt_module = Extension('ltc_scrypt',
                               sources = ['scryptmodule.c',
                                          'scrypt.c',
                                          'scrypt-sse2.c'],
                               include_dirs=['.'],
                               define_macros=[('USE_SSE2',1)],
                               libraries=['crypto']
                              )

setup (name = 'ltc_scrypt',
       version = '1.0',
       description = 'Bindings for scrypt proof of work used by Litecoin',
       ext_modules = [ltc_scrypt_module])

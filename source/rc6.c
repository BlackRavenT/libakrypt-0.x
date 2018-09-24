//
// Created by tatiana on 02.09.18.
//
/* ----------------------------------------------------------------------------------------------- */
#include <stdint.h>
#include <stdlib.h>
#include <ak_bckey.h>
#include <ak_tools.h>
#include <ak_parameters.h>

/* ---------------------------------------------------------------------------------------------- */
#ifdef LIBAKRYPT_HAVE_BUILTIN_XOR_SI128
#ifdef __x86_64__
#define LIBAKRYPT_RC6_M32
#endif
#endif
/*
#ifdef LIBAKRYPT_RC6_M32
static __m128i kuz_mat_enc128[16][256];
static __m128i kuz_mat_dec128[16][256];
#else
static ak_uint128 kuz_mat_enc128[16][256];
 static ak_uint128 kuz_mat_dec128[16][256];
#endif*/

/* ----------------------------------------------------------------------------------------------- */

#define RC6_ROUNDS  20              /* Количество раундов */
#define RC6_LENGTH  256             /* Длина ключа */
#define W           32              /* Длина машинного слова */
#define P32         0xB7E15163      /* Константа от экспоненты */
#define Q32         0x9E3779B9      /* Константа от золотого сечения */
#define LG_W        5               /* Двоичный логарифм от W */

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Раундовые ключи */
struct rc6_expanded_keys
{
    ak_uint32 k[2*RC6_ROUNDS + 4];
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Структура с внутренними данными секретного ключа */
struct rc6_ctx
{
    /*! \brief раундовые ключи для алгоритма зашифрования */
    struct rc6_expanded_keys encryptkey;
    /*! \brief раундовые ключи для алгоритма расшифрования */
    struct rc6_expanded_keys decryptkey;
    /*! \brief маски для раундовых ключей алгоритма зашифрования */
    struct rc6_expanded_keys encryptmask;
    /*! \brief маски для раундовых ключей алгоритма расшифрования */
    struct rc6_expanded_keys decryptmask;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождения памяти, занимаемой развернутыми ключами */
/* ----------------------------------------------------------------------------------------------- */
static int rc6_delete_keys(ak_skey skey)
{
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if(skey == NULL)
        return ak_error_message(ak_error_null_pointer,
                __func__ , "using a null pointer to secret key");
    if(skey->data == NULL)
        return ak_error_message(ak_error_null_pointer,
                __func__ , "using a null pointer to secret key internal data");

    /* теперь очистка и освобождение памяти */
    if((error = skey->generator.random(&skey->generator,
            skey->data, sizeof(struct rc6_ctx))) != ak_error_ok)
    {
        ak_error_message(error, __func__, "incorrect wiping an internal data");
        memset(skey->data, 0, sizeof (struct rc6_ctx));
    }
    if(skey->data != NULL)
    {
        free(skey->data);
        skey->data = NULL;
    }

    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция циклического сдвига 32-битного слова влево */
ak_uint32 sdvigl(ak_uint32 a, ak_uint32 n)
{
    return (a << n) | (a >> (32 - n));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция циклического сдвига 32-битного слова вправо */
ak_uint32 sdvigr(ak_uint32 a, ak_uint32 n)
{
    return (a >> n) | (a << (32 - n));
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция развертки ключа */
static int rc6_schedule_keys(ak_skey skey)
{
    int i = 0, j = 0, k = 0, mask = 0;
    ak_uint32 a = 0, b = 0;
    struct rc6_expanded_keys *ekey = NULL, *mkey = NULL,
                             *dkey = NULL, *xkey = NULL;

    /* выполняем стандартные проверки */
    if(skey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__ ,
                "using a null pointer to secret key");
    /* проверяем целостность ключа */
    if(skey->check_icode(skey) != ak_true)
        return ak_error_message(ak_error_wrong_key_icode,
                __func__ , "using key with wrong integrity code");
    /* удаляем былое */
    if(skey->data != NULL)
        rc6_delete_keys(skey);

    /* готовим память для переменных */
    if((skey->data =            /* далее, по-возможности, выделяем выравненную память */
#ifdef LIBAKRYPT_HAVE_STDALIGN
        aligned_alloc(16,
#else
        malloc(
#endif
        sizeof(struct rc6_ctx))) == NULL)
                return ak_error_message(ak_error_out_of_memory, __func__ ,
                "wrong allocation of internal data");

    /* получаем указатели на области памяти */
    ekey = &((struct rc6_ctx *) skey->data)->encryptkey;
    mkey = &((struct rc6_ctx *) skey->data)->encryptmask;
    dkey = &((struct rc6_ctx *) skey->data)->decryptkey;
    xkey = &((struct rc6_ctx *) skey->data)->decryptmask;

    /* вырабатываем маски */
    skey->generator.random(&skey->generator, mkey, sizeof(struct rc6_expanded_keys));
    skey->generator.random(&skey->generator, xkey, sizeof(struct rc6_expanded_keys));

    /* Развертка начальной последовательности раундовых ключей */
    ak_uint32 *l = calloc(8, sizeof(ak_uint32));    // вспомогателный массив L[0,..c-1]
    memcpy(l, skey->key.data, W);

    ekey->k[0] = dkey->k[0] = P32;                  //((ak_uint32*)skey->data)[0] = P32;
    for(i = 1; i <= 2*RC6_ROUNDS+3; ++i)
        //((ak_uint32*)skey->data)[i] = ((ak_uint32*)skey->data)[i-1] + Q32;
        ekey->k[i] = dkey->k[i] = ekey->k[i - 1] + Q32;

    /* Наложим маску на первый блок */
    ekey->k[0] ^= mkey->k[0];
    dkey->k[0] ^= xkey->k[0];

    /* Развертка раундовых ключей */
    i = 0;
    for(k=1; k < 3*(2*RC6_ROUNDS + 4) + 1; ++k)
    {
/*?*/   if (mask < RC6_LENGTH/W)
        {
            l[j] -= ((ak_uint32*)skey->mask.data)[j];
            mask++;
        }
        a = ekey->k[i] = dkey->k[i] = sdvigl(ekey->k[i] + a + b, 3);
/*?*/   ekey->k[i] ^= mkey->k[i]; dkey->k[i] ^= xkey->k[i];
        b = l[j] = sdvigl(l[j] + a + b, a + b);
        i = (i+1) % (2*RC6_ROUNDS+4);
        j = (j+1) % (RC6_LENGTH/W);
    }
    free(l);
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция смены маски ключа                                                               */
/* ----------------------------------------------------------------------------------------------- */
static int rc6_remask_xor(ak_skey skey)
{
    size_t idx = 0;
    ak_uint32 mask[20], *kptr = NULL, *mptr = NULL;
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if(skey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__ ,
                "using a null pointer to secret key");
    if(skey->key.data == NULL)
        return ak_error_message(ak_error_null_pointer, __func__ ,
                "using undefined key buffer");
    if(skey->key.size != 32)
        return ak_error_message(ak_error_wrong_length, __func__ ,
                "key length is wrong");
    if(skey->mask.data == NULL)
        return ak_error_message(ak_error_null_pointer, __func__ ,
                "using undefined mask buffer");

    /* перемаскируем ключ */
    if((error = skey->generator.random(&skey->generator, mask, skey->key.size )) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong generation random key mask");

    for(idx = 0; idx < 4; idx++)
    {
        ((ak_uint32 *) skey->key.data)[idx] ^= mask[idx];
        ((ak_uint32 *) skey->key.data)[idx] ^= ((ak_uint32 *) skey->mask.data)[idx];
        ((ak_uint32 *) skey->mask.data)[idx] = mask[idx];
    }

    /* перемаскируем раундовые ключи зашифрования */
    if((error = skey->generator.random(&skey->generator, mask, (RC6_ROUNDS*2 + 4)*sizeof(ak_uint32))) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong generation random key mask");

    kptr = (ak_uint32 *) (&((struct rc6_ctx *)skey->data)->encryptkey);
    mptr = (ak_uint32 *) (&((struct rc6_ctx *)skey->data)->encryptmask);
    for(idx = 0; idx < RC6_ROUNDS*2 + 4; idx++)
    {
        kptr[idx] ^= mask[idx];
        kptr[idx] ^= mptr[idx];
        mptr[idx] = mask[idx];
    }

    /* перемаскируем раундовые ключи расшифрования */
    if((error = skey->generator.random(&skey->generator, mask, (RC6_ROUNDS*2 + 4)*sizeof(ak_uint32))) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong generation random key mask");

    kptr = (ak_uint32 *) (&((struct rc6_ctx *)skey->data)->decryptkey);
    mptr = (ak_uint32 *) (&((struct rc6_ctx *)skey->data)->decryptmask);
    for(idx = 0; idx < RC6_ROUNDS*2 + 4; idx++)
    {
        kptr[idx] ^= mask[idx];
        kptr[idx] ^= mptr[idx];
        mptr[idx] = mask[idx];
    }

    /* удаляем старое */
    memset(mask, 0, (RC6_ROUNDS*2 + 4)*sizeof(ak_uint32));
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция зашифрования блока */
static void rc6_encrypt(ak_skey skey, ak_pointer in, ak_pointer out)
{

    int       i = 0;
    ak_uint32 v = 0, u = 0, t = 0;
    struct rc6_expanded_keys *ekey = &((struct rc6_ctx *) skey->data)->encryptkey;
    struct rc6_expanded_keys *mkey = &((struct rc6_ctx *) skey->data)->encryptmask;

    register  ak_uint32 A = ((ak_uint32 *)in)[0];
    register  ak_uint32 B = ((ak_uint32 *)in)[1];
    register  ak_uint32 C = ((ak_uint32 *)in)[2];
    register  ak_uint32 D = ((ak_uint32 *)in)[3];

    B += ekey->k[0] ^ mkey->k[0];       //((ak_uint32 *)(skey->data))[0];
    D += ekey->k[1] ^ mkey->k[1];       //((ak_uint32 *)(skey->data))[1];

    for(i = 1; i < RC6_ROUNDS+1; ++i)
    {
        t = sdvigl((B*(2*B + 1)), LG_W);
        u = sdvigl((D*(2*D + 1)), LG_W);
        A = sdvigl(A^t, u) + ekey->k[2*i] ^ mkey->k[2*i];           //((ak_uint32*)skey->data)[2*i];
        C = sdvigl(C^u, v) + ekey->k[2*i + 1] ^ mkey->k[2*i + 1];   //((ak_uint32*)skey->data)[2*i + 1];
        t = A;
        A = B;
        B = C;
        C = D;
        D = t;
    }

    A += ekey->k[2*RC6_ROUNDS + 2] ^ mkey->k[2*RC6_ROUNDS + 2];     //((ak_uint32*)skey->data)[2*RC6_ROUNDS + 2];
    C += ekey->k[2*RC6_ROUNDS + 3] ^ mkey->k[2*RC6_ROUNDS + 3];     //((ak_uint32*)skey->data)[2*RC6_ROUNDS + 3];

    ((ak_uint32 *)out)[0] = A;
    ((ak_uint32 *)out)[1] = B;
    ((ak_uint32 *)out)[2] = C;
    ((ak_uint32 *)out)[3] = D;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция расшифрования блока */
static void rc6_decrypt(ak_skey skey, ak_pointer in, ak_pointer out)
{
    int       i = 0;
    ak_uint32 v = 0, u = 0, t = 0;
    struct rc6_expanded_keys *dkey = &((struct rc6_ctx *) skey->data)->decryptkey;
    struct rc6_expanded_keys *xkey = &((struct rc6_ctx *) skey->data)->decryptmask;

    register ak_uint32 A = ((ak_uint32 *)in)[0];
    register ak_uint32 B = ((ak_uint32 *)in)[1];
    register ak_uint32 C = ((ak_uint32 *)in)[2];
    register ak_uint32 D = ((ak_uint32 *)in)[3];

    C -= dkey->k[2*RC6_ROUNDS + 3] ^ xkey->k[2*RC6_ROUNDS + 3];         //((ak_uint32*)skey->data)[2*RC6_ROUNDS + 3];
    A -= dkey->k[2*RC6_ROUNDS + 2] ^ xkey->k[2*RC6_ROUNDS + 2];         //((ak_uint32*)skey->data)[2*RC6_ROUNDS + 2];

    for(i = RC6_ROUNDS; i > 0; --i)
    {
        t = D;
        D = C;
        C = B;
        B = A;
        A = t;
        t = sdvigl((B*(2*B + 1)), LG_W);
        u = sdvigl((D*(2*D + 1)), LG_W);
        C = sdvigr((C - (dkey->k[2*i + 1] ^ xkey->k[2*i + 1])), v)^u;   //((ak_uint32*)skey->data)[2*i + 1])
        A = sdvigr((A - (dkey->k[2*i] ^ xkey->k[2*i])), u)^v;           //(ak_uint32*)skey->data)[2*i])
    }

    D -= dkey->k[1] ^ xkey->k[1];                                       //((ak_uint32*)skey->data)[1];
    B -= dkey->k[0] ^ xkey->k[0];                                       //((ak_uint32*)skey->data)[0];

    ((ak_uint32 *)out)[0] = A;
    ((ak_uint32 *)out)[1] = B;
    ((ak_uint32 *)out)[2] = C;
    ((ak_uint32 *)out)[3] = D;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализируете контекст ключа
    После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.
    @param bkey Контекст секретного ключа алгоритма блочного шифрования.
    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_rc6(ak_bckey bkey)
{
    int error = ak_error_ok;
    if(bkey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                "using null pointer to block cipher key context");

    /* создаем ключ алгоритма шифрования и определяем его методы */
    if((error = ak_bckey_create(bkey, 32, 16)) != ak_error_ok)
        return ak_error_message(error, __func__,
                "wrong initalization of block cipher key context");

    /* устанавливаем OID алгоритма шифрования */
    if((bkey->key.oid = ak_oid_find_by_name("rc6")) == NULL)
    {
        error = ak_error_get_value();
        ak_error_message(error, __func__, "wrong search of predefined rc6 block cipher OID");
        ak_bckey_destroy(bkey);
        return error;
    };

    /* устанавливаем ресурс использования серетного ключа */
    bkey->key.resource.counter = ak_libakrypt_get_option("kuznechik_cipher_resource");

    /* устанавливаем методы */
    bkey->key.data          = NULL;
    bkey->key.set_mask      = ak_skey_set_mask_xor;
    bkey->key.remask        = rc6_remask_xor;
    bkey->key.set_icode     = ak_skey_set_icode_xor;
    bkey->key.check_icode   = ak_skey_check_icode_xor;

    bkey->schedule_keys     = rc6_schedule_keys;
    bkey->delete_keys       = rc6_delete_keys;
    bkey->encrypt           = rc6_encrypt;
    bkey->decrypt           = rc6_decrypt;
    return error;
}

/* ----------------------------------------------------------------------------------------------- */
/*! Тестирование                                                                                   */
/* ----------------------------------------------------------------------------------------------- */
ak_bool ak_bckey_test_rc6(void)
{
    char *str = NULL;
    struct bckey bkey;
    int error = ak_error_ok, audit = ak_log_get_level();

    /* тестовый ключ из ГОСТ Р 34.12-2015, приложение А.1 */
    ak_uint8 testkey[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
            0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe};

    /* открытый текст из ГОСТ Р 34.12-2015, приложение А.1, подлежащий зашифрованию */
    ak_uint8 in[16] = {
            0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0, 0xf1};

    /* зашифрованный блок из ГОСТ Р 34.12-2015 */
    ak_uint8 out[16] = {
            0xc8, 0x24, 0x18, 0x16, 0xf0, 0xd7, 0xe4, 0x89, 0x20, 0xad, 0x16, 0xa1, 0x67, 0x4e, 0x5d, 0x48};

/*    /* открытый текст из ГОСТ Р 34.13-2015, приложение А.1, подлежащий зашифрованию
//    ak_uint32 inlong[16] = {
//            0xbbaa9988, 0xffeeddcc, 0x55667700, 0x11223344, 0xcceeff0a, 0x8899aabb, 0x44556677, 0x00112233,
//            0xeeff0a00, 0x99aabbcc, 0x55667788, 0x11223344, 0xff0a0011, 0xaabbccee, 0x66778899, 0x22334455 };
//
//    /* результат зашифрования в режиме простой замены
//    ak_uint32 outecb[16] = {
//            0xb9d4edcd, 0x5a468d42, 0xbebc2430, 0x7f679d90, 0x6718d08b, 0x285452d7, 0x6e0032f9, 0xb429912c,
//            0x3bd4b157, 0xf3f5a531, 0x9d247cee, 0xf0ca3354, 0xaa8ada98, 0x3a02c4c5, 0xe830b9eb, 0xd0b09ccd };
*/

    ak_uint8 myout[64];


    /* 1. Создаем контекст ключа алгоритма Кузнечик и устанавливаем значение ключа */
    if((error = ak_bckey_create_rc6(&bkey)) != ak_error_ok)
    {
        ak_error_message(error, __func__, "incorrect initialization of rc6 secret key context");
        return ak_false;
    }

    if((error = ak_bckey_context_set_ptr(&bkey, testkey, sizeof(testkey), ak_false)) != ak_error_ok)
    {
        ak_error_message(ak_error_get_value(), __func__, "wrong creation of test key");
        return ak_false;
    }

    /* 2. Тестируем зашифрование/расшифрование одного блока                                         */
    bkey.encrypt(&bkey.key, in, myout);
    if(!ak_ptr_is_equal( myout, out, 16))
    {
        ak_error_message_fmt(ak_error_not_equal_data, __func__ ,
                "the one block encryption test of RC6 is wrong");
        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 16, ak_true));
        free(str);
        ak_log_set_message(str = ak_ptr_to_hexstr(out, 16, ak_true));
        free(str);
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if(audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__ ,
                "the one block encryption test of RC6 is Ok");

    bkey.decrypt(&bkey.key, out, myout);
    if(!ak_ptr_is_equal(myout, in, 16))
    {
        ak_error_message_fmt(ak_error_not_equal_data, __func__ ,
                "the one block decryption test of RC6 is wrong");
        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 16, ak_true));
        free(str);
        ak_log_set_message(str = ak_ptr_to_hexstr(in, 16, ak_true));
        free(str);
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if(audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__ ,
                "the one block decryption test of RC6 is Ok");

/*    /* 3. Тестируем режим простой замены
//    if((error = ak_bckey_context_encrypt_ecb(&bkey, inlong, myout, 64)) != ak_error_ok)
//    {
//        ak_error_message_fmt(error, __func__ , "wrong ecb mode encryption");
//        ak_bckey_destroy(&bkey);
//        return ak_false;
//    }
//    if(!ak_ptr_is_equal(myout, outecb, 64))
//    {
//        ak_error_message_fmt(ak_error_not_equal_data, __func__ ,
//                "the ecb mode encryption test of RC6 is wrong");
//        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 64, ak_true);
//        free(str);
//        ak_log_set_message(str = ak_ptr_to_hexstr(outecb, 64, ak_true));
//        free(str);
//        ak_bckey_destroy(&bkey);
//        return ak_false;
//    }
//    if(audit >= ak_log_maximum)
//        ak_error_message(ak_error_ok, __func__ ,
//                "the ecb mode encryption test of RC6 is Ok");
//
//    if((error = ak_bckey_context_decrypt_ecb(&bkey, outecb, myout, 64)) != ak_error_ok)
//    {
//        ak_error_message_fmt(error, __func__ , "wrong ecb mode decryption");
//        ak_bckey_destroy(&bkey);
//        return ak_false;
//    }
//    if(!ak_ptr_is_equal(myout, inlong, 64))
//    {
//        ak_error_message_fmt(ak_error_not_equal_data, __func__ ,
//                "the ecb mode decryption test of RC6 is wrong");
//        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 64, ak_true));
//        free(str);
//        ak_log_set_message(str = ak_ptr_to_hexstr(inlong, 64, ak_true));
//        free(str);
//        ak_bckey_destroy(&bkey);
//        return ak_false;
//    }
//    if(audit >= ak_log_maximum)
//        ak_error_message(ak_error_ok, __func__ ,
//                "the ecb mode decryption test of RC6 is Ok");
//
//    /* 4. Тестируем режим гаммирования (счетчика) согласно ГОСТ Р34.13-2015
//    if(( error = ak_bckey_context_xcrypt( &bkey, inlong, myout, 64, ivctr, 8 )) != ak_error_ok ) {
//        ak_error_message_fmt( error, __func__ , "wrong counter mode encryption" );
//        ak_bckey_destroy( &bkey );
//        return ak_false;
//    }
//    if( !ak_ptr_is_equal( myout, outctr, 64 )) {
//        ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
//                              "the counter mode encryption test from GOST R 34.13-2015 is wrong");
//        ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
//        ak_log_set_message( str = ak_ptr_to_hexstr( outctr, 64, ak_true )); free( str );
//        ak_bckey_destroy( &bkey );
//        return ak_false;
//    }
//    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
//                                                    "the counter mode encryption test from GOST R 34.13-2015 is Ok" );
//
//    if(( error = ak_bckey_context_xcrypt( &bkey, outctr, myout, 64, ivctr, 8 )) != ak_error_ok ) {
//        ak_error_message_fmt( error, __func__ , "wrong counter mode decryption" );
//        ak_bckey_destroy( &bkey );
//        return ak_false;
//    }
//    if( !ak_ptr_is_equal( myout, inlong, 64 )) {
//        ak_error_message_fmt( ak_error_not_equal_data, __func__ ,
//                              "the counter mode decryption test from GOST R 34.13-2015 is wrong");
//        ak_log_set_message( str = ak_ptr_to_hexstr( myout, 64, ak_true )); free( str );
//        ak_log_set_message( str = ak_ptr_to_hexstr( inlong, 64, ak_true )); free( str );
//        ak_bckey_destroy( &bkey );
//        return ak_false;
//    }
//    if( audit >= ak_log_maximum ) ak_error_message( ak_error_ok, __func__ ,
//                                                    "the counter mode decryption test from GOST R 34.13-2015 is Ok" );
*/
    /* уничтожаем ключ и выходим */
    ak_bckey_destroy(&bkey);
    return ak_true;
}

/* ----------------------------------------------------------------------------------------------- */
/*                                                                                           rc6.c */
/* ----------------------------------------------------------------------------------------------- */

/* ----------------------------------------------------------------------------------------------- */
/*  Copyright (c) 2014 - 2018 by Axel Kenzo, axelkenzo@mail.ru                                     */
/*                                                                                                 */
/*  Разрешается повторное распространение и использование как в виде исходного кода, так и         */
/*  в двоичной форме, с изменениями или без, при соблюдении следующих условий:                     */
/*                                                                                                 */
/*   1. При повторном распространении исходного кода должно оставаться указанное выше уведомление  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий.                   */
/*   2. При повторном распространении двоичного кода должна сохраняться указанная выше информация  */
/*      об авторском праве, этот список условий и последующий отказ от гарантий в документации     */
/*      и/или в других материалах, поставляемых при распространении.                               */
/*   3. Ни имя владельца авторских прав, ни имена его соратников не могут быть использованы в      */
/*      качестве рекламы или средства продвижения продуктов, основанных на этом ПО без             */
/*      предварительного письменного разрешения.                                                   */
/*                                                                                                 */
/*  ЭТА ПРОГРАММА ПРЕДОСТАВЛЕНА ВЛАДЕЛЬЦАМИ АВТОРСКИХ ПРАВ И/ИЛИ ДРУГИМИ СТОРОНАМИ "КАК ОНА ЕСТЬ"  */
/*  БЕЗ КАКОГО-ЛИБО ВИДА ГАРАНТИЙ, ВЫРАЖЕННЫХ ЯВНО ИЛИ ПОДРАЗУМЕВАЕМЫХ, ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ИМИ, ПОДРАЗУМЕВАЕМЫЕ ГАРАНТИИ КОММЕРЧЕСКОЙ ЦЕННОСТИ И ПРИГОДНОСТИ ДЛЯ КОНКРЕТНОЙ */
/*  ЦЕЛИ. НИ В КОЕМ СЛУЧАЕ НИ ОДИН ВЛАДЕЛЕЦ АВТОРСКИХ ПРАВ И НИ ОДНО ДРУГОЕ ЛИЦО, КОТОРОЕ МОЖЕТ    */
/*  ИЗМЕНЯТЬ И/ИЛИ ПОВТОРНО РАСПРОСТРАНЯТЬ ПРОГРАММУ, КАК БЫЛО СКАЗАНО ВЫШЕ, НЕ НЕСЁТ              */
/*  ОТВЕТСТВЕННОСТИ, ВКЛЮЧАЯ ЛЮБЫЕ ОБЩИЕ, СЛУЧАЙНЫЕ, СПЕЦИАЛЬНЫЕ ИЛИ ПОСЛЕДОВАВШИЕ УБЫТКИ,         */
/*  ВСЛЕДСТВИЕ ИСПОЛЬЗОВАНИЯ ИЛИ НЕВОЗМОЖНОСТИ ИСПОЛЬЗОВАНИЯ ПРОГРАММЫ (ВКЛЮЧАЯ, НО НЕ             */
/*  ОГРАНИЧИВАЯСЬ ПОТЕРЕЙ ДАННЫХ, ИЛИ ДАННЫМИ, СТАВШИМИ НЕПРАВИЛЬНЫМИ, ИЛИ ПОТЕРЯМИ ПРИНЕСЕННЫМИ   */
/*  ИЗ-ЗА ВАС ИЛИ ТРЕТЬИХ ЛИЦ, ИЛИ ОТКАЗОМ ПРОГРАММЫ РАБОТАТЬ СОВМЕСТНО С ДРУГИМИ ПРОГРАММАМИ),    */
/*  ДАЖЕ ЕСЛИ ТАКОЙ ВЛАДЕЛЕЦ ИЛИ ДРУГОЕ ЛИЦО БЫЛИ ИЗВЕЩЕНЫ О ВОЗМОЖНОСТИ ТАКИХ УБЫТКОВ.            */
/*                                                                                                 */
/*   ak_bckey.h                                                                                    */
/* ----------------------------------------------------------------------------------------------- */
#ifndef __AK_BCKEY_H__
#define __AK_BCKEY_H__

/* ----------------------------------------------------------------------------------------------- */
 #include <ak_skey.h>

/* ----------------------------------------------------------------------------------------------- */
/* предварительное описание */
 struct bckey;
/*! \brief Указатель на структуру ключа блочного алгоритма шифрования. */
 typedef struct bckey *ak_bckey;

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция создания ключа блочного алгоритма шифрования. */
 typedef int ( ak_function_bckey_create ) ( ak_bckey );
/*! \brief Функция зашифрования/расширования одного блока информации. */
 typedef void ( ak_function_bckey )( ak_skey, ak_pointer, ak_pointer );
/*! \brief Функция, предназначенная для зашифрования/расшифрования области памяти заданного размера */
 typedef int ( ak_function_bckey_encrypt )( ak_bckey, ak_pointer, ak_pointer, size_t,
                                                                                ak_pointer, size_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Секретный ключ блочного алгоритма шифрования. */
 struct bckey {
  /*! \brief Указатель на секретный ключ */
   struct skey key;
  /*! \brief Буффер, для хранения синхропосылки. Длина буффера совпадает с длиной блока */
   struct buffer ivector;
  /*! \brief Функция заширования одного блока информации */
   ak_function_bckey *encrypt;
  /*! \brief Функция расширования одного блока информации */
   ak_function_bckey *decrypt;
  /*! \brief Функция развертки ключа */
   ak_function_skey *schedule_keys;
  /*! \brief Функция уничтожения развернутых ключей */
   ak_function_skey *delete_keys;
};

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация ключа алгоритма блочного шифрования. */
 int ak_bckey_create( ak_bckey , size_t , size_t );
/*! \brief Очистка ключа алгоритма блочного шифрования. */
 int ak_bckey_destroy( ak_bckey );
/*! \brief Удаление ключа алгоритма блочного шифрования. */
 ak_pointer ak_bckey_delete( ak_pointer );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Инициализация контекста секретного ключа алгоритма блочного шифрования Магма. */
 int ak_bckey_create_magma( ak_bckey );
/*! \brief Инициализация контекста секретного ключа алгоритма блочного шифрования Кузнечик. */
int ak_bckey_create_kuznechik( ak_bckey );
/*! \brief Инициализация контекста секретного ключа алгоритма блочного шифрования RC6. */
int ak_bckey_create_rc6( ak_bckey );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Присвоение контексту ключа алгоритма блочного шифрования константного значения. */
 int ak_bckey_context_set_ptr( ak_bckey, const ak_pointer , const size_t , const ak_bool );
/*! \brief Присвоение контексту ключа алгоритма блочного шифрования случайного значения. */
 int ak_bckey_context_set_random( ak_bckey , ak_random );
/*! \brief Присвоение контексту ключа алгоритма блочного шифрования значения, выработанного из пароля. */
 int ak_bckey_context_set_password( ak_bckey , const ak_pointer , const size_t ,
                                                                const ak_pointer , const size_t );
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Зашифрование данных в режиме простой замены. */
 int ak_bckey_context_encrypt_ecb( ak_bckey , ak_pointer , ak_pointer , size_t );
/*! \brief Расшифрование данных в режиме простой замены. */
 int ak_bckey_context_decrypt_ecb( ak_bckey , ak_pointer , ak_pointer , size_t );
/*! \brief Зашифрование/расшифрование данных в режиме гаммирования из ГОСТ Р 34.13-2015. */
 int ak_bckey_context_xcrypt( ak_bckey , ak_pointer , ak_pointer , size_t , ak_pointer , size_t );
/*! \brief Дальнейшее зашифрование/расшифрование в режиме гаммирования из ГОСТ Р 34.13-2015. */
 int ak_bckey_context_xcrypt_update( ak_bckey , ak_pointer , ak_pointer , size_t );

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Тестирование корректной работы алгоритма блочного шифрования Магма. */
 ak_bool ak_bckey_test_magma( void );
/*! \brief Инициализация таблиц, необходимых для быстрой работы алгоритма блочного шифрования Кузнечик (ГОСТ Р 34.12-2015).                                                       */
 ak_bool ak_bckey_init_kuznechik_tables( void );
/*! \brief Тестирование корректной работы алгоритма блочного шифрования Кузнечик. */
ak_bool ak_bckey_test_kuznechik( void );
/*! \brief Тестирование корректной работы алгоритма блочного шифрования RC6. */
ak_bool ak_bckey_test_rc6( void );

#endif
/* ----------------------------------------------------------------------------------------------- */
/*                                                                                     ak_bckey.h  */
/* ----------------------------------------------------------------------------------------------- */

#include <Python.h>
#include <python2.7/structmember.h>

#include "./scrypt.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <arpa/inet.h>

static PyObject * emptyTuple;


static PyObject *scrypt_getpowhash(PyObject *self, PyObject *args)
{
    char *output;
    PyObject *value;
    PyStringObject *input;
    if (!PyArg_ParseTuple(args, "S", &input))
        return NULL;
    Py_INCREF(input);
    output = PyMem_Malloc(32);
    scrypt_1024_1_1_256((char *)PyString_AsString((PyObject*) input), output);
    Py_DECREF(input);
    value = Py_BuildValue("s#", output, 32);
    PyMem_Free(output);
    return value;
}

static PyMethodDef ScryptMethods[] = {
    { "getPoWHash", scrypt_getpowhash, METH_VARARGS, "Returns the proof of work hash using scrypt" },
    { NULL, NULL, 0, NULL }
};

typedef struct {
  PyObject_HEAD
  PyObject *state;
  PyObject *buffer;
} CSha256;

static PyObject * cSha256_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
  CSha256 * self = (CSha256 *)type->tp_alloc(type, 0);
  if (self == NULL) abort();
  self->state = NULL;
  self->buffer = NULL;
  if (PyErr_Occurred() != NULL) abort();
  return (PyObject *) self;
}

static void cSha256_dealloc(CSha256* self) {
  Py_XDECREF(self->state);
  Py_XDECREF(self->buffer);
  self->ob_type->tp_free((PyObject*)self);
}

static void cSha256_internal_update(CSha256 * self, PyObject * dataObj) {
  // Shared code for both init and update
  char * data = NULL;
  Py_ssize_t dataLength = 0;
  PyString_AsStringAndSize(dataObj, &data, &dataLength);
  
  char * extra = NULL;
  Py_ssize_t extraLength = 0;
  if (self->buffer != NULL) {
      extra = PyByteArray_AsString(self->buffer);
      extraLength = PyByteArray_Size(self->buffer);
  }
  uint64_t totalLength = dataLength + extraLength;
  uint64_t originalExtraLength = extraLength;
  SHA256_CTX * ctxp;
  ctxp = (SHA256_CTX *) PyByteArray_AsString(self->state);
  
  if (totalLength > 64) {  // We have enough to move the SHA2 state forward
      if (extraLength > 0) {
        
        SHA256_Update(ctxp, extra, extraLength);
        Py_DECREF(self->buffer);
        self->buffer = NULL;
        
        extraLength = 0; // We absorbed it all
        extra = NULL;
      }
      // SHA2 uses blocks of 64 bytes or 16 uint32_t, so we floor to the nearest 64 bytes
      uint64_t dataLengthToBlockBoundary = ((totalLength / 64) * 64) - originalExtraLength;
//       printf("%lu %lu %lu %lu", dataLength, originalExtraLength, totalLength, dataLengthToBlockBoundary);
      if (dataLength < dataLengthToBlockBoundary) abort();
      SHA256_Update(ctxp, data, dataLengthToBlockBoundary);
      
      self->buffer = PyByteArray_FromStringAndSize(data + dataLengthToBlockBoundary, dataLength - dataLengthToBlockBoundary); // Implicit memcpy
      if (self->buffer == NULL) abort();
      Py_INCREF(self->buffer);
      
      dataLength -= dataLengthToBlockBoundary;  // Move the start of data foward to the portion we havent consumed yet
      data += dataLengthToBlockBoundary; 
  }
  
  if (dataLength > 0) {
    if (extraLength > 0) {
        // Add space for our extra data and fill it in
        PyByteArray_Resize(self->buffer, extraLength + dataLength);
        memcpy(PyByteArray_AsString(self->buffer) + extraLength, data, dataLength);
    } else { // No extra data previously, start fresh
        self->buffer = PyByteArray_FromStringAndSize(data, dataLength); // Implicit memcpy]
        Py_INCREF(self->buffer);
    }
  }
  
}

static int cSha256_init(CSha256 * self, PyObject *args, PyObject *argsDict) {
  
  PyObject *dataObj = NULL;
  PyObject *stateObj = NULL;
  PyObject *extraObj = NULL;
  uint64_t sha256_length = 0;  // be lazy and just use big integer types
  
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  
  char * s;
  size_t i;
  
  static char *kwlist[] = {"data", "_", NULL}; // First arg: data to be hashed
                                               // Second arg: initial state of the hash machine
  PyArg_ParseTupleAndKeywords(args, argsDict, "|O(SSK)", kwlist, &dataObj, &stateObj, &extraObj, &sha256_length);
    
  if (stateObj != NULL) { // Recreate hash data in the SHA2 state
      if (PyString_Size(stateObj) != 256/8)
        PyErr_SetString(PyExc_RuntimeError, "State wasnt 256 bits: what kind of SHA do you think this is?");
      s = PyString_AsString(stateObj);
      memcpy(&(ctx.h), s, 256/8);
      for (i = 0; i < 8; i++) {  // SHA2 is big-endian always (aka network byte order) so swap if necessary
          ctx.h[i] = ntohl(ctx.h[i]);
      }
  }
  if (extraObj != NULL) {
    Py_ssize_t extraLength = 0;
    extraLength = PyString_Size(extraObj);
    if (sha256_length > 0)
      sha256_length -= extraLength*8; // Already counted, don't double count -- the *8 is a part of SHA2 spec
  }
  if (sha256_length > 0) {  // Recreate length tracking part of the SHA2 state
      ctx.Nl = (uint32_t)(sha256_length & 0xffffffffUL);  // First 32-bits
      ctx.Nh = (uint32_t)(sha256_length >> 32);
  }
  self->state = PyByteArray_FromStringAndSize((const char *)&ctx, sizeof(ctx));  // Store openssl's ctx structuer in a mutable byte array
  if (self->state == NULL) abort();                                              // Implicit memcpy
  Py_INCREF(self->state);
  
  if (extraObj != NULL) {
    cSha256_internal_update(self, extraObj);
  }
  if (dataObj != NULL) {
    cSha256_internal_update(self, dataObj);
  }
  if (self == NULL) abort();
  if (PyErr_Occurred() != NULL) abort();
  return 0;
}

static CSha256 * cSha256_update(CSha256 * self, PyObject *args, PyObject *argsDict) {
  PyObject *dataObj = NULL;
  static char *kwlist[] = {"data", NULL};  // Takes one argument of type object
  PyArg_ParseTupleAndKeywords(args, argsDict, "|O", kwlist, &dataObj);
  if (dataObj != NULL && dataObj != Py_None) { // If we got an argument
    cSha256_internal_update(self, dataObj); // Hash it
  }
  if (self == NULL) abort();
  Py_INCREF(self);
  return self;
}

static void cSha256_digest_internal(CSha256 * self, PyObject *args, unsigned char * digest) {
  // Shared code for both digest routines
  SHA256_CTX * ctxp;
  ctxp = (SHA256_CTX *) PyByteArray_AsString(self->state);
  if (ctxp == NULL) abort();
  if (PyByteArray_Size(self->state) != sizeof(SHA256_CTX)) abort();
  if (self->buffer != NULL) {
    Py_ssize_t extraLength = 0;
    char * extra = NULL;
    extraLength = PyByteArray_Size(self->buffer);
    extra = PyByteArray_AsString(self->buffer);
    if (extra == NULL) abort();
    SHA256_Update(ctxp, extra, extraLength);
  }  
  SHA256_Final(digest, ctxp);
  Py_DECREF(self->state);
  self->state = NULL;
}

static PyObject* cSha256_digest(CSha256 * self, PyObject *args) {
  PyObject *digestObj = NULL;
  unsigned char digest[256/8];
  cSha256_digest_internal(self, args, digest);
  digestObj = PyString_FromStringAndSize((char *) digest, 256/8); // Implicit memcpy
  if (digestObj == NULL) abort();
  return digestObj;
}

static void bin2hex(unsigned char * bin, char * hex, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        PyOS_snprintf(hex + (i*2), 3, "%02hhx", bin[i]);
    }
}

static PyObject* cSha256_hexdigest(CSha256 * self, PyObject *args) {
  PyObject *digestObj = NULL;
  unsigned char digest[256/8];
  char hex[(256/4)+1];
  cSha256_digest_internal(self, args, digest);
  bin2hex(digest, hex, 256/8);
  digestObj = PyString_FromStringAndSize(hex, 256/4); // Implicit memcpy
  if (digestObj == NULL) abort();
  return digestObj;
}

static CSha256 * cSha256_copy(CSha256 * self, PyObject *args) {
  CSha256 * copy = (CSha256 *) self->ob_type->tp_new(self->ob_type, emptyTuple, emptyTuple);
  copy->state = NULL;
  copy->buffer = NULL;
  if (self->state != NULL) {
    copy->state = PyByteArray_FromStringAndSize(PyByteArray_AsString(self->state), PyByteArray_Size(self->state)); // Implicit memcpy
    if (copy->state == NULL) abort();
    Py_INCREF(copy->state);
  }
  if (self->buffer != NULL) {
    copy->buffer = PyByteArray_FromStringAndSize(PyByteArray_AsString(self->buffer), PyByteArray_Size(self->buffer)); // Implicit memcpy
    if (copy->buffer == NULL) abort();
    Py_INCREF(copy->buffer);
  }
  if (copy == NULL) abort();
  return copy;
}

static PyObject * cSha256_getattro(CSha256 * self, PyObject * attr_name) {
  char * name = PyString_AsString(attr_name);
  SHA256_CTX * ctxp = (SHA256_CTX *) PyByteArray_AsString(self->state);
  PyObject * r = NULL;
  uint32_t h[8];  // Temp storage SHA2 internal state
  if (strcmp(name, "state") == 0) {
    memcpy(h, &(ctxp->h), 256/8);
    size_t i;
    for (i = 0; i < 8; i++) {  // SHA2 is big-endian always so unswap if necessary
      h[i] = htonl(ctxp->h[i]);
    }
    r = PyString_FromStringAndSize((char *) h, 256/8); // Implicit memcpy
  } else if (strcmp(name, "buf") == 0) {
    r = PyString_FromStringAndSize(PyByteArray_AsString(self->buffer), PyByteArray_Size(self->buffer)); // Implicit memcpy
  } else if (strcmp(name, "length") == 0) {
    uint64_t extraLength = 0;
    if (self->buffer != NULL)
      extraLength = PyByteArray_Size(self->buffer);
    r = PyLong_FromLongLong(((((uint64_t) ctxp->Nl) & (((uint64_t) ctxp->Nh) << 32)) + (extraLength * 8)));
  } else {
    r = PyObject_GenericGetAttr((PyObject *) self, attr_name);
  }
  if (PyErr_Occurred() != NULL) abort();
  if (r == NULL) abort();
  Py_INCREF(r);
  return r;
}

static PyMethodDef cSha256Methods[] = {
    {"__init__", (PyCFunction) cSha256_init, METH_KEYWORDS|METH_VARARGS, "Prime a new SHA256 hash or resume a hash machine"},
    {"update", (PyCFunction) cSha256_update, METH_KEYWORDS|METH_VARARGS, "Add data to a SHA256 hash machine"},
    {"digest", (PyCFunction) cSha256_digest, METH_NOARGS, "Finalize and return a SHA256 hash value"},
    {"hexdigest", (PyCFunction) cSha256_hexdigest, METH_NOARGS, "Finalize and return a SHA256 hash value in hexadecimal"},
    {"copy", (PyCFunction) cSha256_copy, METH_NOARGS, "Clone a SHA256 hash machine"},
    { NULL, NULL, 0, NULL }
};


static PyMemberDef cSha256Members[] = {
  {"state", T_OBJECT_EX, offsetof(CSha256, state), 0, "Internal hash machine state"},
  {"buffer", T_OBJECT_EX, offsetof(CSha256, buffer), 0, "Internal hash machine buffer"},
  { NULL, 0, 0, 0, NULL }
};

static PyTypeObject CSha256_Type = {
  PyObject_HEAD_INIT(NULL)
  0,                         /*ob_size*/
  "ltc_scrypt.CSha256",      /*tp_name*/
  sizeof(CSha256),           /*tp_basicsize*/
  0,                         /*tp_itemsize*/
  (destructor)cSha256_dealloc,           /*tp_dealloc*/
  0,                         /*tp_print*/
  0,                         /*tp_getattr*/
  0,                         /*tp_setattr*/
  0,                         /*tp_compare*/
  0,                         /*tp_repr*/
  0,                         /*tp_as_number*/
  0,                         /*tp_as_sequence*/
  0,                         /*tp_as_mapping*/
  0,                         /*tp_hash */
  0,                         /*tp_call*/
  0,                         /*tp_str*/
  (getattrofunc) cSha256_getattro,          /*tp_getattro*/
  0,                         /*tp_setattro*/
  0,                         /*tp_as_buffer*/
  Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
  "SHA256 Class written in C",           /* tp_doc */
  0,                         /* tp_traverse */
  0,                         /* tp_clear */
  0,                         /* tp_richcompare */
  0,                         /* tp_weaklistoffset */
  0,                         /* tp_iter */
  0,                         /* tp_iternext */
  cSha256Methods,            /* tp_methods */
  cSha256Members,            /* tp_members */  // We provide our own getattr
  0,                         /* tp_getset */
  0,                         /* tp_base */
  0,                         /* tp_dict */
  0,                         /* tp_descr_get */
  0,                         /* tp_descr_set */
  0,                         /* tp_dictoffset */
  (initproc)cSha256_init,              /* tp_init */
  0,                         /* tp_alloc */
  cSha256_new,               /* tp_new */
};


PyMODINIT_FUNC initltc_scrypt(void) {
    scrypt_detect_sse2();  // Detect SSE support on module import
    
    emptyTuple = PyTuple_New(0); // Initialize an empty tuple for convienence
    Py_INCREF(emptyTuple);
    
    PyObject *module = Py_InitModule("ltc_scrypt", ScryptMethods);  // Add scrypt method
    
    PyType_Ready(&CSha256_Type);  // Add CSha256 class
    Py_INCREF(&CSha256_Type);
    PyModule_AddObject(module, "cSha256", (PyObject *) &CSha256_Type);
    PyModule_AddObject(module, "sha256", (PyObject *) &CSha256_Type);
}

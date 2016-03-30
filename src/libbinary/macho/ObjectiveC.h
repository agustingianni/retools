#include <cstdint>

namespace ObjectiveC {

namespace v1 {

struct image_info_t {
    uint32_t version;
    uint32_t flags;
};

template<typename pointer_t>
struct property_t {
    pointer_t name; // const char *
    pointer_t attributes; // const char *
};

template<typename pointer_t>
struct property_list_t {
    uint32_t size;
    uint32_t count;
    property_t<pointer_t> elements[0];
};

template<typename pointer_t>
struct class_ext_t {
    uint32_t size;
    pointer_t weak_ivar_layout; // const uint8_t *
    pointer_t property_lists; // void *
};

template<typename pointer_t>
struct category_struct_t {
    pointer_t category_name; // char *
    pointer_t class_name; // char *
    pointer_t instance_methods; // void *
    pointer_t class_methods; // void *
    pointer_t protocols; // void *
};

template<typename pointer_t>
struct class_struct_ext_t {
    pointer_t isa; // void *
    pointer_t super_class; // char *
    pointer_t name; // char *
    uint32_t version;
    uint32_t info;
    uint32_t instance_size;
    pointer_t ivars; // void *
    pointer_t methods; // void *
    uint32_t cache;
    pointer_t protocols; // void *
    pointer_t ivar_layout; // const uint8_t *
    pointer_t ext; // void *
};

template<typename pointer_t>
struct instance_vars_struct_t {
    pointer_t name; // char *
    pointer_t type; // char *
    uint32_t offset;
};

template<typename pointer_t>
struct instance_vars_struct_list_t {
    uint32_t count;
    instance_vars_struct_t<pointer_t> elements[0];
};

template<typename pointer_t>
struct method_t {
    pointer_t method_name; // void *
    pointer_t method_types; // char *
    pointer_t method_imp; // void *
};

template<typename pointer_t>
struct method_list_t {
    uint32_t unk;
    uint32_t count;
    method_t<pointer_t> elements[0];
};

template<typename pointer_t>
struct module_info_struct_t {
    uint32_t version;
    uint32_t size;
    pointer_t name; // char *
    pointer_t symbols; // void *
};

template<typename pointer_t>
struct protocol_list_struct_t {
    uint32_t unk;
    uint32_t count;
    pointer_t list[0]; // protocol_ref_t
};

template<typename pointer_t>
struct protocol_struct_t {
    pointer_t isa; // void *
    pointer_t protocol_name; // char *
    pointer_t protocol_list; // void *
    pointer_t instance_methods; // void *
    pointer_t class_methods; // void *
};

template<typename pointer_t>
struct symtab_struct_t {
    uint32_t sel_ref_cnt;
    uint32_t refs;
    uint16_t cls_def_count;
    uint16_t cat_def_count;
    pointer_t defs[0]; // __objc_class_struct_ext *
};

template<typename pointer_t>
struct object_t {
    pointer_t isa; // void *
};

template<typename pointer_t>
struct message_ref_t {
    pointer_t sel; // char *
};

}

namespace v2 {
struct image_info_t {
    uint32_t version;
    uint32_t flags;
};

struct meth_list_t {
    uint32_t entrysize;
    uint32_t count;
};

struct prot_list_t {
    uint64_t count;
};

struct ivar_list_t {
    uint32_t entrysize;
    uint32_t count;
};

struct prop_list_t {
    uint32_t entrysize;
    uint32_t count;
};

// Values for class_ro_t->flags
#define RO_META               (1<<0)  // class is a metaclass
#define RO_ROOT               (1<<1)  // class is a root class
#define RO_HAS_CXX_STRUCTORS  (1<<2)  // class has .cxx_construct/destruct implementations
#define RO_HAS_LOAD_METHOD    (1<<3)  // class has +load implementation
#define RO_HIDDEN             (1<<4)  // class has visibility=hidden set
#define RO_EXCEPTION          (1<<5)  // class has attribute(objc_exception): OBJC_EHTYPE_$_ThisClass is non-weak
#define RO_REUSE_ME           (1<<6)  // this bit is available for reassignment
#define RO_IS_ARR             (1<<7)  // class compiled with -fobjc-arc (automatic retain/release)
#define RO_HAS_CXX_DTOR_ONLY  (1<<8)  // class has .cxx_destruct but no .cxx_construct (with RO_HAS_CXX_STRUCTORS)
#define RO_FROM_BUNDLE        (1<<29) // class is in an unloadable bundle - must never be set by compiler
#define RO_FUTURE             (1<<30) // class is unrealized future class - must never be set by compiler
#define RO_REALIZED           (1<<31) // class is realized - must never be set by compiler

template<typename pointer_t>
struct class_ro_t {
    uint32_t flags;
    uint32_t ivar_base_start;
    uint32_t ivar_base_size;
    uint32_t reserved;
    pointer_t ivar_lyt; // void *
    pointer_t name; // char *
    pointer_t base_meths; // meth_list_t *
    pointer_t base_prots; // prot_list_t *
    pointer_t ivars; // ivar_list_t *
    pointer_t weak_ivar_lyt; // void *
    pointer_t base_props; // prop_list_t *
};

template<typename pointer_t>
struct category_t {
    pointer_t name; // char *
    pointer_t _class; // class_ro_t *
    pointer_t inst_meths; // meth_list_t *
    pointer_t class_meths; // meth_list_t *
    pointer_t prots; // prot_list_t *
    pointer_t props; // prop_list_t *
};

template<typename pointer_t>
struct class_t {
    pointer_t isa; // class_t *
    pointer_t superclass; // class_t *
    pointer_t cache; // void *
    pointer_t vtable; // void *
    pointer_t info; // class_ro_t *
};

template<typename pointer_t>
struct ivar_t {
    pointer_t ptr; // void *
    pointer_t name; // char *
    pointer_t type; // char *
    uint32_t align;
    uint32_t size;
};

template<typename pointer_t>
struct meth_t {
    pointer_t name; // char *
    pointer_t types; // char *
    pointer_t imp; // void *
};

template<typename pointer_t>
struct prop_t {
    pointer_t name; // char *
    pointer_t attr; // char *
};

template<typename pointer_t>
struct prot_t {
    pointer_t isa; // void *
    pointer_t name; // char *
    pointer_t prots; // prot_list_t *
    pointer_t inst_meths; // meth_list_t *
    pointer_t class_meths; // meth_list_t *
    pointer_t opt_inst_meths; // meth_list_t *
    pointer_t opt_class_meths; // meth_list_t *
    pointer_t inst_props; // prop_list_t *
};

template<typename pointer_t>
struct message_ref_t {
    pointer_t imp; // void *
    pointer_t sel; // char *
};

}

}

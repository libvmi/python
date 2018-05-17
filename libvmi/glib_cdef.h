typedef int    gint;
typedef gint   gboolean;
typedef void* gpointer;
typedef const void *gconstpointer;
typedef unsigned int    guint;
typedef struct _GHashTable  GHashTable;

typedef guint (*GHashFunc)(gconstpointer key);
typedef gboolean (*GEqualFunc)(gconstpointer a, gconstpointer b);

typedef struct _GSList GSList;

struct _GSList {
  gpointer data;
  GSList *next;
};

GHashTable* g_hash_table_new               (GHashFunc       hash_func,
                                            GEqualFunc      key_equal_func);

gboolean    g_hash_table_insert            (GHashTable     *hash_table,
                                            gpointer        key,
                                            gpointer        value);

void        g_hash_table_destroy           (GHashTable     *hash_table);

guint    g_str_hash     (gconstpointer  v);
gboolean g_str_equal    (gconstpointer  v1, gconstpointer  v1);

void g_free (gpointer mem);

void g_slist_free (GSList *list);

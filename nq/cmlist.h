/*************************************************************************
 * Copyright 2011-2012 by Visuality Systems, Ltd.
 *
 *                     All Rights Reserved
 *
 * This item is the property of Visuality Systems, Ltd., and contains
 * confidential, proprietary, and trade-secret information. It may not
 * be transferred from the custody or control of Visuality Systems, Ltd.,
 * except as expressly authorized in writing by an officer of Visuality
 * Systems, Ltd. Neither this item nor the information it contains may
 * be used, transferred, reproduced, published, or disclosed, in whole
 * or in part, and directly or indirectly, except as expressly authorized
 * by an officer of Visuality Systems, Ltd., pursuant to written agreement.
 **************************************************************************/

#ifndef _CMLIST_H_ 
#define _CMLIST_H_

#include "syapi.h"          /* system-dependent */
#include "cmcommon.h"       /* basic types */

/* -- Defines -- */
#define CM_LISTITEM_NOLOCK    0x0000	/* do not lock */
#define CM_LISTITEM_LOCK  	  0x0001	/* lock item, guard required */
#define CM_LISTITEM_EXCLUSIVE 0x0002 	/* lock item, no guard required */

/* -- Structures -- */

struct _cmitem;         /* forward definition */
struct _cmlist;         /* forward definition */
struct _cmreference;    /* forward definition */

/* Description
   This structure describes a linked list. Its elements should
   be <link CMItem> structures. */
typedef struct _cmlist
{
    SYMutex guard;           /* List protection. */
    struct _cmitem * first;  /* Pointer to the first item in the list or NULL when the list is empty. */
    struct _cmitem * last;   /* Pointer to the last item in the list or NULL when the list is empty. */
    NQ_BOOL          isUsed; /* set to FALSE only after the list was disposed */
#if SY_DEBUGMODE
    NQ_CHAR * name; /* List name (for debug purposes only). */
#endif /* SY_DEBUGMODE */
} CMList; /* Linked list. */

/* Description
   This structure describes a inked list item.
   
   Besides of the standard linked list behavior this module
   features lock count and unlock callback function. An item is
   locked when another item is referencing it. Before the
   referencing item is disposed, it first unlocks all items that
   it references. If the lock count for a referenced item
   becomes zero, NQ calls this item's unlock callback (unless it
   is NULL).
   Note
     * Another structure, to inherit the linked list behavior
       should contain CMItem field as its very first field.
     * NQ copies item names into freshly allocated memory.       */
typedef struct _cmitem
{
    struct _cmitem * next;  /* Pointer to the next item in the list. */
    struct _cmitem * prev;  /* Pointer to the previous item in the list. */
    NQ_COUNT locks;     /* Number of locks on this item. */
    NQ_BOOL (*callback)(struct _cmitem * item);  /* Unlock callback. This value may be NULL. */
    struct _cmlist * master;  /* The master list. */
    struct _cmlist references;  /* List of references. */
    NQ_WCHAR * name;      /* pointer to item name */
    NQ_BOOL beingDisposed;    /* <i>TRUE</i> when this item is being disposed. */
    NQ_BOOL findable;         /* TRUE if item can be found in list */
    NQ_BOOL isStatic;         /* TRUE if item should not be disposed , Default - FALSE*/  
#if SY_DEBUGMODE
    void (*dump)(struct _cmitem * item);  /* Dump callback. This value may be NULL. */
#endif /* SY_DEBUGMODE */
    SYMutex * guard;          /* Item protection. */
} CMItem; /* Linked list item. */

/* Description
   This structure describes a reference to another <link CMItem> object. */
typedef struct _cmreference 
{
    CMItem item;  /* Linked list chain. */
    CMItem * ref; /* The referenced item. */
} CMReference; /* Linked list. */

/* Description
   Variable of this type is used to enumerate items in the list.
   The same thread can create just one iterator on a given list,
   so that nested iterators are not allowed.                     */
typedef struct _cmiterator
{
    CMItem * next;  /* Pointer to the next element. */
    CMList * list;  /* Pointer to the master list. */
} CMIterator; /* List iterator. */

/* -- Functions -- */

/* Description
   This function initialize a linked list and prepares it for
   usage.
   
   After initialization it does not contain any items.
   Initializing linked list does not dispose its items. To
   dispose all linked list items call <link cmListRemoveAndDisposeAll@CMList *, cmListRemoveAndDisposeAll()>.
   Parameters
   list :  Pointer to the list.
   Returns
   None                                                                                                       */
void cmListStart(CMList * list);

/* Description
   This function releases resources associated with a linked list.
   
   It also removes and disposes all list items (if any).
   Parameters      
   list :  Pointer to the list.
   Returns
   None                                                                                                       */
void cmListShutdown(CMList * list);

/* Description
   This function check a list and reports whether it has at least one item.
   Parameters
   list :  Pointer to the list.
   Returns
   TRUE if list has at least one item, FALSE otherwise.             */
#define cmListHasItems(_list_) ((_list_)->first != NULL)

/* Description
   This function removes and disposes all items in the list.
   
   After a call to this function the list is empty and can be
   used again.
   Parameters
   list :  Pointer to the list.
   Returns
   None                                                       */
void cmListRemoveAndDisposeAll(CMList * list);

/* Description
   This function initialized an item.

   Parameters
   item :  Pointer to the item to remove.
   Returns                                   */
void cmListItemInit(CMItem * item);

/* Description
   This function adds an item to the list.
   
   The <i>item</i> parameter below can be NULL, which allows to
   delegate into this function an immediate result of memory
   allocation without checking it.
   Parameters
   list :      Pointer to the list.
   item :      Pointer to the new item. This value may be NULL.
   callback :  Callback function to be called when the item is
               fully unlocked.
   Returns
   TRUE when the item was linked or FALSE code otherwise.
   Possible errors are:
     * The <i>item</i> parameter was NULL;
     * List is corrupted.                                       */
NQ_BOOL cmListItemAdd(CMList * list, CMItem * item, NQ_BOOL (*callback)(CMItem * item));

/* Description
   This function creates new item, initializes it but does not
   add it to any list.
   Parameters
   size :  Item size in bytes.
   name :  Pointer to item name. NQ copies the name so that the
           origin may be released after this call.
   lock : Whether to lock the item if found or not.
   Returns
   Pointer to the new item or NULL on failure. Possible error
   reasons are:
     * Out of memory.                                           */
CMItem * cmListItemCreate(NQ_UINT size, const NQ_WCHAR * name , NQ_UINT32 lock);
   
   /* Description
      This function creates new item and adds it to the list.
      
      The <i>item</i> parameter below can be NULL, which allows to
      delegate into this function an immediate result of memory
      allocation without checking it.
      Parameters
      list :      Pointer to the list.
      size :      Item size in bytes.
      name :      Pointer to item name. NQ copies the name so that
                  the origin may be released after this call.
      callback :  Callback function to be called when the item is
                  fully unlocked.
      lock :	  Mask indicating lock for exclusive use.
      Returns
      Pointer to the new item or NULL on failure. Possible error
      reasons are:
        * Out of memory;
        * List is corrupted.                                       */
CMItem * cmListItemCreateAndAdd(CMList * list, NQ_UINT size, const NQ_WCHAR * name, NQ_BOOL (*callback)(CMItem * item) , NQ_UINT32 lock);

/* Description
   This function removes an item from the list.
   
   The item lock count remains unchanged and the item is not
   disposed.
   
   If the lock count of the object to be removed is not zero,
   this functions performs all the mentioned above but does not
   remove the item from its list.
   Parameters
   item :  Pointer to the item to remove.
   Returns
   TRUE if the item was successfully removed and FALSE if its
   lock count is not zero.                                      */
NQ_BOOL cmListItemRemove(CMItem * item);

/* Description
   This function dispose memory used by the item.
   
   Before disposing the item this function removes all
   references. For each reference, the lock count of its
   referenced object is decreased and checked for a zero value.
   If it reaches zero, the referenced object is removed from its
   list and disposed.
   Parameters
   item :  Pointer to the item to dispose.
   Returns
   None                                                          */
void cmListItemDispose(CMItem * item);

/* Description
   This function removes an item from the list and disposes it.
   
   Before disposing the item this function removes all
   references. For each reference, the lock count of its
   referenced object is decreased and checked for a zero value.
   If it reaches zero, the referenced object is removed from its
   list and disposed.
   
   If the lock count of the object to be removed is not zero,
   this functions performs all the mentioned above but does not
   remove the item from its list and does not dispose it
   Parameters
   item :  Pointer to the item to remove and dispose.
   Returns
   TRUE if the item was successfully removed and FALSE if its
   lock count is not zero.                                       */
NQ_BOOL cmListItemRemoveAndDispose(CMItem * item);

/* Description
   This function adds a reference to the list of references of
   the <i>referencing</i> item.
   
   After reference is created, this function increments the lock
   count of the referenced object.
   
   Each of the item parameter below can be NULL, which allows to
   delegate into this function an immediate result of memory
   allocation without checking it.
   Parameters
   referencing :  Pointer to the referencing item.
   referenced :   Pointer to the referenced item.
   Returns
   None */
void cmListItemAddReference(CMItem * referencing, CMItem * referenced);

/* Description
   This function removes a reference.
   
   Each of the item parameter below can be NULL, which allows to
   delegate into this function an immediate result of memory
   allocation without checking it.
   Parameters
   referencing :  Pointer to the referencing item.
   referenced :   Pointer to the referenced item.
   Returns
   None */
void cmListItemRemoveReference(CMItem * referencing, CMItem * referenced);

/* Description
   This call starts a critical section for editing item.
   
   It makes sense to only protect those items that are members
   of a list. Since referenced items are always list members,
   this condition seems to be enough.
   
   A critical section, started in this call should be finished
   by calling <link cmListItemGive@CMItem *, cmListItemGive()>.
   Parameters
   item :  Item to edit.
   Returns
   None                                                         */
void cmListItemTake(CMItem * item); 

/* Description
   This call ends a critical section for editing item. The
   critical section should be previously stated by calling <link cmListItemTake@CMItem *, cmListItemTake()>.
   Parameters
   item :  Item being edited.
   Returns
   None                                                                                                      */
void cmListItemGive(CMItem * item); 

/* Description
   This function starts iterating items in the list.
   
   On return from this call NQ creates an iterator that may be
   used later in <link cmListIteratorNext@CMIterator *, cmListIteratorNext()>
   calls.
   
   NQ starts a critical section which continues until
   enumeration expires (i.e., - <link cmListIteratorNext@CMIterator *, cmListIteratorNext()>
   \returns NULL).
   
   The same thread can create just one iterator on a given list,
   so that nested iterators are not allowed.
   Parameters
   list :  The list to enumerate items in.
   iterator :  The iterator object to initialize.
   Returns
   None.                                                                            */
void cmListIteratorStart(CMList * list, CMIterator * iterator);

/* Description
   This function terminates iteration when the end-of-iteration
   was not reached (i.e., <link cmListIteratorNext@CMIterator *, cmListIteratorNext>()
   did not return NULL yet). .
   Parameters
   iterator :  The iterator to terminate.
   Returns
   None */
void cmListIteratorTerminate(CMIterator * iterator);

/* Description
   This function returns next item in the list. When there are
   no more items, it leaves the critical section.
   Parameters
   iterator :  Pointer to iterator, previously initialized using <link cmListIteratorStart@CMList *@CMIterator *, cmListIteratorStart()>.
               After this call, NQ "increments" this value so
               that it will be ready to bring next item.
   Returns
   Next item in the list or NULL when no more items are
   available.                                                                                                                             */
CMItem * cmListIteratorNext(CMIterator * iterator);

/* Description
   This call checks iterator for end-of-iteration condition.
   Parameters
   _iterator_ :  The iterator object to check.
   Returns
   TRUE when a subsequent call to <link cmListIteratorNext@CMIterator *, cmListIteratorNext>()
   will bring an item and FALSE when it will bring NULL.                                       */
#define cmListIteratorHasNext(_iterator_) ((_iterator_)->next != NULL) 

/* Description
   This function locks item by increasing its lock count.
   Parameters
   item :  Pointer to the item to lock.
   Returns
   None                                                   */
void cmListItemLock(CMItem * item);

/* Description
   This function unlocks item by decreasing its lock count. When
   lock count reaches zero, item is removed from the list and
   disposed.
   Parameters
   item :  Pointer to the item to unlock.
   Returns
   None                                                          */
void cmListItemUnlock(CMItem * item);

/* Description
   This function checks lock count on an item. When it is zero, item is removed from 
   the list and disposed.
   Parameters
   item :  Pointer to the item to unlock.
   Returns
   None                                                          */
void cmListItemCheck(CMItem * item);

/* Description
   This function looks for an item in the list by its name. 
   Parameters
   list :  Pointer to the list.
   name :  Pointer to the item name.
   ignoringCase : Whether to ignore case.
   lock: Whether to lock the item if found or not.
   Returns
   Pointer to the item or NULL if item was not found.                                                          */
CMItem * cmListItemFind(CMList * list, const NQ_WCHAR * name, NQ_BOOL ignoringCase , NQ_BOOL lock);


#if SY_DEBUGMODE
/* Description
   This function prints a list of items. For each item it prints
   all its common fields and also calls the item's <link _cmitem::dump, dump>
   callback, unless it is NULL.
   Parameters
   list :  Pointer to the list to dump.
   Returns
   None                                                                       */
void cmListDump(CMList * list);

#endif /* SY_DEBUGMODE */

#endif /* _CMLIST_H_ */

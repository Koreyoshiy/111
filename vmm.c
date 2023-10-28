#include <vmm.h>
#include <sync.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <error.h>
#include <pmm.h>
#include <riscv.h>
#include <swap.h>

/* 
  vmm design include two parts: mm_struct (mm) & vma_struct (vma)
  mm is the memory manager for the set of continuous virtual memory  
  area which have the same PDT. vma is a continuous virtual memory area.
  There a linear link list for vma & a redblack link list for vma in mm.
---------------
  mm related functions:
   golbal functions
     struct mm_struct * mm_create(void)
     void mm_destroy(struct mm_struct *mm)
     int do_pgfault(struct mm_struct *mm, uint_t error_code, uintptr_t addr)
--------------
  vma related functions:
   global functions
     struct vma_struct * vma_create (uintptr_t vm_start, uintptr_t vm_end,...)
     void insert_vma_struct(struct mm_struct *mm, struct vma_struct *vma)
     struct vma_struct * find_vma(struct mm_struct *mm, uintptr_t addr)
   local functions
     inline void check_vma_overlap(struct vma_struct *prev, struct vma_struct *next)
---------------
   check correctness functions
     void check_vmm(void);
     void check_vma_struct(void);
     void check_pgfault(void);
*/

// szx func : print_vma and print_mm
void print_vma(char *name, struct vma_struct *vma){//打印vma_struct的信息
	cprintf("-- %s print_vma --\n", name);
	cprintf("   mm_struct: %p\n",vma->vm_mm);//vm_mm是一个指向使用相同页目录表的一组vma_struct的指针。
	cprintf("   vm_start,vm_end: %x,%x\n",vma->vm_start,vma->vm_end);//虚拟连续内存区域的起始地址和结束地址（结束地址为vm_end，但不包含vm_end本身）
	cprintf("   vm_flags: %x\n",vma->vm_flags);//标志位
	cprintf("   list_entry_t: %p\n",&vma->list_link);//按照vma的起始地址对vma进行排序的线性链表链接
}

void print_mm(char *name, struct mm_struct *mm){//打印mm_struct的信息。遍历了mm_struct中的所有vma_struct，并调用print_vma函数打印每个vma_struct的信息
	cprintf("-- %s print_mm --\n",name);
	cprintf("   mmap_list: %p\n",&mm->mmap_list);//按照vma起始地址排序的线性链表链接
	cprintf("   map_count: %d\n",mm->map_count);//相同页目录表的这组vma的数量
	list_entry_t *list = &mm->mmap_list;
	for(int i=0;i<mm->map_count;i++){//遍历输出每一个vma的信息
		list = list_next(list);
		print_vma(name, le2vma(list,list_link));
	}
}

static void check_vmm(void);
static void check_vma_struct(void);
static void check_pgfault(void);

// mm_create -  alloc a mm_struct & initialize it.
struct mm_struct *
mm_create(void) {//创建mm_struct结构体并进行初始化。分配内存空间并初始化成员变量mmap_list、mmap_cache、pgdir和map_count等
    struct mm_struct *mm = kmalloc(sizeof(struct mm_struct));
    //分配一个mm_struct结构体的内存空间并将其地址赋值给指针变量mm。
    //mm_struct是用于管理一组连续虚拟内存区域的内存管理结构体。
    //通过调用kmalloc函数，分配了足够大小的内存空间来存储mm_struct结构体，
    //并将其地址赋值给指针变量mm，以便后续对该结构体的操作和访问。
    //这样可以在运行时动态地创建和管理mm_struct结构体，以满足虚拟内存管理的需求。


    if (mm != NULL) {//初始化为空
        list_init(&(mm->mmap_list));
        mm->mmap_cache = NULL;
        mm->pgdir = NULL;
        mm->map_count = 0;

        if (swap_init_ok) swap_init_mm(mm);//在交换管理器初始化成功的情况下，调用swap_init_mm函数来初始化mm结构体
        else mm->sm_priv = NULL;//否则将交换管理器的私有数据初始化为空
    }
    return mm;
}

// vma_create - alloc a vma_struct & initialize it. (addr range: vm_start~vm_end)
struct vma_struct *
vma_create(uintptr_t vm_start, uintptr_t vm_end, uint_t vm_flags) {//创建vma_struct结构体并进行初始化。分配内存空间并初始化vm_start、vm_end和vm_flags成员变量。
    struct vma_struct *vma = kmalloc(sizeof(struct vma_struct));
    /*
    分配一个vma_struct结构体的内存空间并将其地址赋值给指针变量vma
    通过调用kamlloc函数，分配了足够大小的内存空间来存储mm_struct结构体，
    并将其地址赋值给指针变量vma，以便后续对该结构体的操作和访问。
    这样可以在运行时动态地创建和管理vma_struct结构体，以满足虚拟内存管理的需求。
    */

    if (vma != NULL) {//如果vma不为空，则将输入的参数赋值为vma的变量
        vma->vm_start = vm_start;
        vma->vm_end = vm_end;
        vma->vm_flags = vm_flags;
    }
    return vma;
}


// find_vma - find a vma  (vma->vm_start <= addr <= vma_vm_end)
struct vma_struct *
find_vma(struct mm_struct *mm, uintptr_t addr) {//在给定的mm_struct中查找包含给定地址的vma_struct。该函数首先检查mmap_cache是否匹配，如果不匹配则遍历mmap_list链表查找匹配的vma_struct。
    struct vma_struct *vma = NULL;
    if (mm != NULL) {
        vma = mm->mmap_cache;//将当前访问的vma赋值给指针变量vma
        if (!(vma != NULL && vma->vm_start <= addr && vma->vm_end > addr)) {//当vma为空或者addr超出vma内存区域时进行进一步查找
                bool found = 0;
                list_entry_t *list = &(mm->mmap_list), *le = list;
                while ((le = list_next(le)) != list) {//遍历mm->mmap_list链表中的每个vma结构体
                    vma = le2vma(le, list_link);
                    if (vma->vm_start<=addr && addr < vma->vm_end) {//如果找到了包含addr的vma结构体，将found标志设置为1，并跳出循环
                        found = 1;
                        break;
                    }
                }
                if (!found) {//如果遍历完整个链表后，没有找到addr的vma结构体，则将vma设置为NULL
                    vma = NULL;
                }
        }
        if (vma != NULL) {//如果找到了合适的vma结构体，将其赋值给mm->mmap_cache，以便下次查找时可以直接使用缓存的vma
            mm->mmap_cache = vma;
        }
    }
    return vma;
}


// check_vma_overlap - check if vma1 overlaps vma2 ?
static inline void
check_vma_overlap(struct vma_struct *prev, struct vma_struct *next) {//用于检查两个相邻的vma_struct是否重叠。
    //断言函数assert，如果断言失败则输出错误信息比那个终端程序执行（括号内即为断言条件）
    assert(prev->vm_start < prev->vm_end);
    assert(prev->vm_end <= next->vm_start);
    assert(next->vm_start < next->vm_end);
}


// insert_vma_struct -insert vma in mm's list link
void
insert_vma_struct(struct mm_struct *mm, struct vma_struct *vma) {//用于将一个vma_struct插入到mm_struct的map_list链表中。该函数根据vma_struct的vm_start值找到插入位置并进行插入操作。
    assert(vma->vm_start < vma->vm_end);//断言判断内存区域是否满足条件
    list_entry_t *list = &(mm->mmap_list);
    list_entry_t *le_prev = list, *le_next;

        list_entry_t *le = list;
        while ((le = list_next(le)) != list) {//遍历每一个vma结构体
            struct vma_struct *mmap_prev = le2vma(le, list_link);//将当前节点转换为vma_struct结构体类型，并赋值给mmap_prev指针变量
            if (mmap_prev->vm_start > vma->vm_start) {//如果当前节点的vm_start大于要插入的vma的vm_start，则跳出循环，找到了插入位置
                break;
            }
            le_prev = le;//将当前节点赋值给le_prev，作为插入位置的前一个节点
        }

    le_next = list_next(le_prev);//获取插入位置的下一个节点

    /* check overlap */
    //检查要插入位置是否会有重叠
    if (le_prev != list) {
        check_vma_overlap(le2vma(le_prev, list_link), vma);
    }
    if (le_next != list) {
        check_vma_overlap(vma, le2vma(le_next, list_link));
    }

    vma->vm_mm = mm;
    list_add_after(le_prev, &(vma->list_link));//将要插入节点插入到le_prev节点的后面

    mm->map_count ++;//增加mm结构体的计数器
}

// mm_destroy - free mm and mm internal fields
void
mm_destroy(struct mm_struct *mm) {

    list_entry_t *list = &(mm->mmap_list), *le;
    while ((le = list_next(list)) != list) {
        list_del(le);
        kfree(le2vma(le, list_link),sizeof(struct vma_struct));  //kfree vma        
    }
    kfree(mm, sizeof(struct mm_struct)); //kfree mm
    mm=NULL;
}

// vmm_init - initialize virtual memory management
//          - now just call check_vmm to check correctness of vmm
void
vmm_init(void) {
    check_vmm();
}

// check_vmm - check correctness of vmm
static void
check_vmm(void) {
    size_t nr_free_pages_store = nr_free_pages();//nr_free_pages()是一个函数调用，用于获取当前系统中的空闲页面数量
    check_vma_struct();
    check_pgfault();

    nr_free_pages_store--;	// szx : Sv39三级页表多占一个内存页，所以执行此操作
    assert(nr_free_pages_store == nr_free_pages());//空闲页面数量是否正确

    cprintf("check_vmm() succeeded.\n");
}

static void
check_vma_struct(void) {//验证mm_struct结构体的创建、插入、查找和销毁功能是否正常
    size_t nr_free_pages_store = nr_free_pages();

    struct mm_struct *mm = mm_create();
    assert(mm != NULL);//断言检查，确保对象创建成功

    int step1 = 10, step2 = step1 * 10;

    //使用循环创建了一系列vma_struct结构体对象，并将它们插入到mm_struct的mmap_list链表中。
    //每个vma_struct对象的起始地址和结束地址都按照一定的规律进行设置
    int i;
    for (i = step1; i >= 1; i --) {
        struct vma_struct *vma = vma_create(i * 5, i * 5 + 2, 0);//i*5为起始地址，i*5+2为结束地址（不含）
        assert(vma != NULL);
        insert_vma_struct(mm, vma);
    }

    for (i = step1 + 1; i <= step2; i ++) {
        struct vma_struct *vma = vma_create(i * 5, i * 5 + 2, 0);
        assert(vma != NULL);
        insert_vma_struct(mm, vma);
    }

    list_entry_t *le = list_next(&(mm->mmap_list));

    for (i = 1; i <= step2; i ++) {
        assert(le != &(mm->mmap_list));
        struct vma_struct *mmap = le2vma(le, list_link);
        assert(mmap->vm_start == i * 5 && mmap->vm_end == i * 5 + 2);
        le = list_next(le);
    }

    for (i = 5; i <= 5 * step2; i +=5) {
        struct vma_struct *vma1 = find_vma(mm, i);
        assert(vma1 != NULL);
        struct vma_struct *vma2 = find_vma(mm, i+1);
        assert(vma2 != NULL);
        struct vma_struct *vma3 = find_vma(mm, i+2);
        assert(vma3 == NULL);
        struct vma_struct *vma4 = find_vma(mm, i+3);
        assert(vma4 == NULL);
        struct vma_struct *vma5 = find_vma(mm, i+4);
        assert(vma5 == NULL);

        assert(vma1->vm_start == i  && vma1->vm_end == i  + 2);
        assert(vma2->vm_start == i  && vma2->vm_end == i  + 2);
    }

    for (i =4; i>=0; i--) {
        struct vma_struct *vma_below_5= find_vma(mm,i);
        if (vma_below_5 != NULL ) {
           cprintf("vma_below_5: i %x, start %x, end %x\n",i, vma_below_5->vm_start, vma_below_5->vm_end); 
        }
        assert(vma_below_5 == NULL);
    }

    mm_destroy(mm);

    assert(nr_free_pages_store == nr_free_pages());//确保销毁后的空闲页面数量与之前存储的值相等

    cprintf("check_vma_struct() succeeded!\n");
}

struct mm_struct *check_mm_struct;

// check_pgfault - check correctness of pgfault handler
static void
check_pgfault(void) {//验证页错误处理函数check_pgfault()的正确性，包括vma_struct的插入、查找和销毁功能，以及对页表项和物理页面的操作
	// char *name = "check_pgfault";
    size_t nr_free_pages_store = nr_free_pages();

    check_mm_struct = mm_create();

    assert(check_mm_struct != NULL);
    struct mm_struct *mm = check_mm_struct;
    pde_t *pgdir = mm->pgdir = boot_pgdir;
    assert(pgdir[0] == 0);

    struct vma_struct *vma = vma_create(0, PTSIZE, VM_WRITE);//起始地址为0.结束地址为PTSIZE，访问权限为VM_WRITE

    assert(vma != NULL);

    insert_vma_struct(mm, vma);

    uintptr_t addr = 0x100;
    assert(find_vma(mm, addr) == vma);//断言检查查找结果与预期是否一致

    int i, sum = 0;
    for (i = 0; i < 100; i ++) {
        *(char *)(addr + i) = i;//将数据写入地址addr开始的内存区域
        sum += i;//计算写入数据的总和
    }
    for (i = 0; i < 100; i ++) {
        sum -= *(char *)(addr + i);//再次循环读取相同的内存区域并将读取的数据从总和中减去
    }
    assert(sum == 0);//断言检查以确保总和为0，以验证写入和读取的数据是否一致

    page_remove(pgdir, ROUNDDOWN(addr, PGSIZE));//移除pgdir中指定地址范围的页表项

    free_page(pde2page(pgdir[0]));//释放相应的物理页面

    pgdir[0] = 0;

    mm->pgdir = NULL;
    mm_destroy(mm);

    check_mm_struct = NULL;
    nr_free_pages_store--;	// szx : Sv39第二级页表多占了一个内存页，所以执行此操作

    assert(nr_free_pages_store == nr_free_pages());

    cprintf("check_pgfault() succeeded!\n");
}
//page fault number
volatile unsigned int pgfault_num=0;

/* do_pgfault - interrupt handler to process the page fault execption
 * @mm         : the control struct for a set of vma using the same PDT
 * @error_code : the error code recorded in trapframe->tf_err which is setted by x86 hardware
 * @addr       : the addr which causes a memory access exception, (the contents of the CR2 register)
 *
 * CALL GRAPH: trap--> trap_dispatch-->pgfault_handler-->do_pgfault
 * The processor provides ucore's do_pgfault function with two items of information to aid in diagnosing
 * the exception and recovering from it.
 *   (1) The contents of the CR2 register. The processor loads the CR2 register with the
 *       32-bit linear address that generated the exception. The do_pgfault fun can
 *       use this address to locate the corresponding page directory and page-table
 *       entries.
 *   (2) An error code on the kernel stack. The error code for a page fault has a format different from
 *       that for other exceptions. The error code tells the exception handler three things:
 *         -- The P flag   (bit 0) indicates whether the exception was due to a not-present page (0)
 *            or to either an access rights violation or the use of a reserved bit (1).
 *         -- The W/R flag (bit 1) indicates whether the memory access that caused the exception
 *            was a read (0) or write (1).
 *         -- The U/S flag (bit 2) indicates whether the processor was executing at user mode (1)
 *            or supervisor mode (0) at the time of the exception.
 */
int
do_pgfault(struct mm_struct *mm, uint_t error_code, uintptr_t addr) {
    int ret = -E_INVAL;
    //try to find a vma which include addr
    struct vma_struct *vma = find_vma(mm, addr);

    pgfault_num++;
    //If the addr is in the range of a mm's vma?
    if (vma == NULL || vma->vm_start > addr) {
        cprintf("not valid addr %x, and  can not find it in vma\n", addr);
        goto failed;
    }

    /* IF (write an existed addr ) OR
     *    (write an non_existed addr && addr is writable) OR
     *    (read  an non_existed addr && addr is readable)
     * THEN
     *    continue process
     */
    uint32_t perm = PTE_U;//可用的页表目录项
    if (vma->vm_flags & VM_WRITE) {//vma的vm_flags是否包含VW_WRITE标志
        perm |= (PTE_R | PTE_W);//perm的值按位或PTE_R和PTE_W，表示该页表项可读可写
    }
    addr = ROUNDDOWN(addr, PGSIZE);//将addr向下对齐到PGSIZE的倍数，以确保地址按页对齐

    ret = -E_NO_MEM;//表示内存不足的错误

    pte_t *ptep=NULL;//ptep指向页表项
    /*
    * Maybe you want help comment, BELOW comments can help you finish the code
    *
    * Some Useful MACROs and DEFINEs, you can use them in below implementation.
    * MACROs or Functions:
    *   get_pte : get an pte and return the kernel virtual address of this pte for la
    *             if the PT contians this pte didn't exist, alloc a page for PT (notice the 3th parameter '1')
    *   pgdir_alloc_page : call alloc_page & page_insert functions to allocate a page size memory & setup
    *             an addr map pa<--->la with linear address la and the PDT pgdir
    * DEFINES:
    *   VM_WRITE  : If vma->vm_flags & VM_WRITE == 1/0, then the vma is writable/non writable
    *   PTE_W           0x002                   // page table/directory entry flags bit : Writeable
    *   PTE_U           0x004                   // page table/directory entry flags bit : User can access
    * VARIABLES:
    *   mm->pgdir : the PDT of these vma
    *
    */


    ptep = get_pte(mm->pgdir, addr, 1);  //(1) try to find a pte, if pte's
                                         //PT(Page Table) isn't existed, then
                                         //create a PT.
    if (*ptep == 0) {
        if (pgdir_alloc_page(mm->pgdir, addr, perm) == NULL) {
            cprintf("pgdir_alloc_page in do_pgfault failed\n");
            goto failed;
        }
    } else {
        /*LAB3 EXERCISE 3: YOUR CODE
        * 请你根据以下信息提示，补充函数
        * 现在我们认为pte是一个交换条目，那我们应该从磁盘加载数据并放到带有phy addr的页面，
        * 并将phy addr与逻辑addr映射，触发交换管理器记录该页面的访问情况
        *
        *  一些有用的宏和定义，可能会对你接下来代码的编写产生帮助(显然是有帮助的)
        *  宏或函数:
        *    swap_in(mm, addr, &page) : 分配一个内存页，然后根据
        *    PTE中的swap条目的addr，找到磁盘页的地址，将磁盘页的内容读入这个内存页
        *    page_insert ： 建立一个Page的phy addr与线性addr la的映射
        *    swap_map_swappable ： 设置页面可交换
        */
       if (swap_init_ok) {
        struct Page *page = NULL;
        // (1) According to the mm AND addr, try to load the content of right disk page into the memory which page managed.
        if ((ret = swap_in(mm, addr, &page)) != 0) {
            cprintf("swap_in in do_pgfault failed\n");
            goto failed;
            }
        page->pra_vaddr = addr;
        // (2) According to the mm, addr AND page, setup the map of phy addr <--> logical addr
        if ((ret = page_insert(mm->pgdir, page, addr, perm)) != 0) {
            cprintf("page_insert in do_pgfault failed\n");
            goto failed;
            }
        // (3) make the page swappable.
        swap_map_swappable(mm, addr, page, 1);
        page->pra_vaddr = addr;
        } else {
            cprintf("no swap_init_ok but ptep is %x, failed\n", *ptep);
            goto failed;
        }
   }

   ret = 0;
failed:
    return ret;
}


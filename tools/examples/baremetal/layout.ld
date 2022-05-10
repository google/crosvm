ENTRY(_start)

/* Crosvm will load our code into 0x200000 + paddr */
MEMORY {
    VMA : ORIGIN = 0x00200000, LENGTH = 0x200000
    RAM : ORIGIN = 0x00000000, LENGTH = 0x200000
}

SECTIONS {


  .bootloader :
  {
      _stack_end = . ;
      *(.boot)
  }> VMA AT>RAM

  .kernel :
  {
    KEEP(*(.text.main))
    *(.text .text.*)
    *(.rodata .rodata.*)
    *(.data .data.*)
    *(.bss .bss.*)
  }> VMA AT>RAM

  DISCARD/ :
  {
    *(.note.gnu.*)
  }

}

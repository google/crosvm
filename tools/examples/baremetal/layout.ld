ENTRY(_start)

/* Crosvm will load our code into 0x200000 + paddr */
MEMORY {
    VMA : ORIGIN = 0x00200000, LENGTH = 0x200000
}

SECTIONS {


  .bootloader :
  {
      _stack_end = . ;
      *(.boot)
  }> VMA

  .kernel :
  {
    KEEP(*(.text.main))
    *(.text .text.*)
    *(.rodata .rodata.*)
    *(.data .data.*)
    *(.bss .bss.*)
  }> VMA

  DISCARD/ :
  {
    *(.note.gnu.*)
  }

}

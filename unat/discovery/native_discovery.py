#!/usr/bin/env python3
"""
Native Discovery Module
Discovers native libraries and functions in Android applications
"""

import logging
import re
import struct
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, field
from pathlib import Path

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.relocation import RelocationSection
    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False
    logging.warning("pyelftools not available. Native discovery features will be limited.")

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logging.warning("capstone not available. Disassembly features will be limited.")


@dataclass
class NativeFunction:
    """Data class to store native function information"""
    name: str
    address: int
    size: int = 0
    type: str = "FUNC"  # FUNC, OBJECT, etc.
    binding: str = "GLOBAL"  # GLOBAL, LOCAL, WEAK
    demangled_name: Optional[str] = None


@dataclass
class NativeLibraryInfo:
    """Data class to store native library information"""
    path: str
    architecture: str
    bit_width: int  # 32 or 64
    endianness: str  # little or big
    has_pie: bool = False
    has_nx: bool = False
    has_canary: bool = False
    has_relro: bool = False
    exported_functions: List[NativeFunction] = field(default_factory=list)
    imported_functions: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    sections: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)


@dataclass
class NativeDiscoveryResult:
    """Data class to store native discovery results"""
    apk_path: str
    total_libraries: int = 0
    total_exported_functions: int = 0
    total_imported_functions: int = 0
    total_strings: int = 0
    libraries: List[NativeLibraryInfo] = field(default_factory=list)


class NativeDiscovery:
    """
    Native Discovery for analyzing native libraries (.so files)
    Uses pyelftools and capstone for static analysis
    """

    # Architecture mapping
    ARCH_MAP = {
        'EM_ARM': 'ARM',
        'EM_AARCH64': 'ARM64',
        'EM_386': 'x86',
        'EM_X86_64': 'x86_64',
        'EM_MIPS': 'MIPS',
    }

    def __init__(self):
        """
        Initialize Native Discovery

        Raises:
            ImportError: If pyelftools is not available
        """
        if not ELFTOOLS_AVAILABLE:
            raise ImportError("pyelftools is required but not installed")

        self.logger = logging.getLogger(__name__)

    def analyze_library(
        self,
        library_path: str,
        extract_strings: bool = True,
        min_string_length: int = 4,
        max_strings: Optional[int] = 1000
    ) -> Optional[NativeLibraryInfo]:
        """
        Analyze a native library file

        Args:
            library_path: Path to the .so file
            extract_strings: Extract printable strings
            min_string_length: Minimum string length to extract
            max_strings: Maximum number of strings to extract

        Returns:
            Optional[NativeLibraryInfo]: Library info or None if failed
        """
        lib_path = Path(library_path)
        if not lib_path.exists():
            self.logger.error(f"Library not found: {library_path}")
            return None

        try:
            with open(library_path, 'rb') as f:
                elf = ELFFile(f)

                # Extract basic info
                lib_info = NativeLibraryInfo(
                    path=str(library_path),
                    architecture=self._get_architecture(elf),
                    bit_width=64 if elf.elfclass == 64 else 32,
                    endianness='little' if elf.little_endian else 'big'
                )

                # Security features
                lib_info.has_pie = self._check_pie(elf)
                lib_info.has_nx = self._check_nx(elf)
                lib_info.has_canary = self._check_canary(elf)
                lib_info.has_relro = self._check_relro(elf)

                # Extract sections
                lib_info.sections = [section.name for section in elf.iter_sections() if section.name]

                # Extract exported functions
                lib_info.exported_functions = self._extract_exported_functions(elf)

                # Extract imported functions
                lib_info.imported_functions = self._extract_imported_functions(elf)

                # Extract dependencies
                lib_info.dependencies = self._extract_dependencies(elf)

                # Extract strings if requested
                if extract_strings:
                    lib_info.strings = self._extract_strings(
                        f,
                        elf,
                        min_length=min_string_length,
                        max_strings=max_strings
                    )

                self.logger.info(
                    f"Analyzed {lib_path.name}: "
                    f"{len(lib_info.exported_functions)} exports, "
                    f"{len(lib_info.imported_functions)} imports, "
                    f"{len(lib_info.strings)} strings"
                )

                return lib_info

        except Exception as e:
            self.logger.error(f"Failed to analyze {library_path}: {e}")
            return None

    def _get_architecture(self, elf: ELFFile) -> str:
        """
        Determine the architecture from ELF header

        Args:
            elf: ELFFile object

        Returns:
            str: Architecture name
        """
        machine = elf.header['e_machine']
        return self.ARCH_MAP.get(machine, machine)

    def _check_pie(self, elf: ELFFile) -> bool:
        """Check if PIE (Position Independent Executable) is enabled"""
        return elf.header['e_type'] == 'ET_DYN'

    def _check_nx(self, elf: ELFFile) -> bool:
        """Check if NX (No-eXecute) is enabled"""
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_STACK':
                # NX enabled if stack is not executable
                return (segment['p_flags'] & 0x1) == 0
        return False

    def _check_canary(self, elf: ELFFile) -> bool:
        """Check if stack canary is present"""
        # Look for __stack_chk_fail symbol
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                for symbol in section.iter_symbols():
                    if '__stack_chk_fail' in symbol.name:
                        return True
        return False

    def _check_relro(self, elf: ELFFile) -> bool:
        """Check if RELRO (Relocation Read-Only) is enabled"""
        for segment in elf.iter_segments():
            if segment['p_type'] == 'PT_GNU_RELRO':
                return True
        return False

    def _extract_exported_functions(self, elf: ELFFile) -> List[NativeFunction]:
        """
        Extract exported functions from symbol table

        Args:
            elf: ELFFile object

        Returns:
            List[NativeFunction]: List of exported functions
        """
        functions = []

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                # Only export global/weak functions
                if symbol['st_info']['bind'] not in ('STB_GLOBAL', 'STB_WEAK'):
                    continue

                # Only functions and objects
                symbol_type = symbol['st_info']['type']
                if symbol_type not in ('STT_FUNC', 'STT_OBJECT'):
                    continue

                # Must have a name and be defined (not imported)
                if not symbol.name or symbol['st_shndx'] == 'SHN_UNDEF':
                    continue

                func = NativeFunction(
                    name=symbol.name,
                    address=symbol['st_value'],
                    size=symbol['st_size'],
                    type='FUNC' if symbol_type == 'STT_FUNC' else 'OBJECT',
                    binding=symbol['st_info']['bind'][4:],  # Remove 'STB_' prefix
                    demangled_name=self._demangle_name(symbol.name)
                )
                functions.append(func)

        return sorted(functions, key=lambda f: f.address)

    def _extract_imported_functions(self, elf: ELFFile) -> List[str]:
        """
        Extract imported functions (undefined symbols)

        Args:
            elf: ELFFile object

        Returns:
            List[str]: List of imported function names
        """
        imports = set()

        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue

            for symbol in section.iter_symbols():
                # Look for undefined symbols (imports)
                if symbol['st_shndx'] == 'SHN_UNDEF' and symbol.name:
                    # Only include functions, not objects
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        imports.add(symbol.name)

        return sorted(list(imports))

    def _extract_dependencies(self, elf: ELFFile) -> List[str]:
        """
        Extract shared library dependencies

        Args:
            elf: ELFFile object

        Returns:
            List[str]: List of dependency names
        """
        dependencies = []

        for section in elf.iter_sections():
            if not isinstance(section, DynamicSection):
                continue

            for tag in section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    dependencies.append(tag.needed)

        return dependencies

    def _extract_strings(
        self,
        file_handle,
        elf: ELFFile,
        min_length: int = 4,
        max_strings: Optional[int] = 1000
    ) -> List[str]:
        """
        Extract printable strings from the library

        Args:
            file_handle: Open file handle
            elf: ELFFile object
            min_length: Minimum string length
            max_strings: Maximum number of strings to extract

        Returns:
            List[str]: List of extracted strings
        """
        strings = set()

        # Common sections to search for strings
        string_sections = ['.rodata', '.data', '.dynstr', '.strtab']

        for section in elf.iter_sections():
            if section.name not in string_sections:
                continue

            data = section.data()
            current_string = b''

            for byte in data:
                # Printable ASCII range
                if 32 <= byte <= 126:
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        try:
                            decoded = current_string.decode('utf-8', errors='ignore')
                            if decoded and not decoded.isspace():
                                strings.add(decoded)
                        except:
                            pass
                    current_string = b''

            # Handle last string
            if len(current_string) >= min_length:
                try:
                    decoded = current_string.decode('utf-8', errors='ignore')
                    if decoded and not decoded.isspace():
                        strings.add(decoded)
                except:
                    pass

        # Limit number of strings
        result = sorted(list(strings))
        if max_strings:
            result = result[:max_strings]

        return result

    def _demangle_name(self, name: str) -> Optional[str]:
        """
        Attempt to demangle C++ symbol names

        Args:
            name: Mangled name

        Returns:
            Optional[str]: Demangled name or None
        """
        # Simple C++ name demangling
        # For full demangling, we'd need c++filt or a dedicated library
        if name.startswith('_Z'):
            # This is a mangled C++ name
            # We'll just return a note for now
            return f"<C++ mangled: {name[:20]}...>" if len(name) > 20 else f"<C++ mangled: {name}>"
        return None

    def discover_from_apk(
        self,
        apk_path: str,
        extract_strings: bool = True,
        min_string_length: int = 4,
        max_strings_per_lib: Optional[int] = 1000
    ) -> Optional[NativeDiscoveryResult]:
        """
        Discover all native libraries in an APK

        Args:
            apk_path: Path to the APK file
            extract_strings: Extract strings from libraries
            min_string_length: Minimum string length
            max_strings_per_lib: Maximum strings per library

        Returns:
            Optional[NativeDiscoveryResult]: Discovery results
        """
        from zipfile import ZipFile

        apk_file = Path(apk_path)
        if not apk_file.exists():
            self.logger.error(f"APK not found: {apk_path}")
            return None

        result = NativeDiscoveryResult(apk_path=str(apk_path))

        try:
            with ZipFile(apk_path, 'r') as apk:
                # Find all .so files
                so_files = [name for name in apk.namelist() if name.endswith('.so')]

                if not so_files:
                    self.logger.warning("No native libraries found in APK")
                    return result

                self.logger.info(f"Found {len(so_files)} native libraries")

                # Extract and analyze each library
                import tempfile
                with tempfile.TemporaryDirectory() as temp_dir:
                    for so_file in so_files:
                        # Extract to temp directory
                        temp_path = Path(temp_dir) / Path(so_file).name
                        with apk.open(so_file) as src, open(temp_path, 'wb') as dst:
                            dst.write(src.read())

                        # Analyze library
                        lib_info = self.analyze_library(
                            str(temp_path),
                            extract_strings=extract_strings,
                            min_string_length=min_string_length,
                            max_strings=max_strings_per_lib
                        )

                        if lib_info:
                            # Update path to show original location in APK
                            lib_info.path = so_file
                            result.libraries.append(lib_info)

                # Calculate totals
                result.total_libraries = len(result.libraries)
                result.total_exported_functions = sum(
                    len(lib.exported_functions) for lib in result.libraries
                )
                result.total_imported_functions = sum(
                    len(lib.imported_functions) for lib in result.libraries
                )
                result.total_strings = sum(
                    len(lib.strings) for lib in result.libraries
                )

                self.logger.info(
                    f"Discovery complete: {result.total_libraries} libraries, "
                    f"{result.total_exported_functions} exports, "
                    f"{result.total_imported_functions} imports"
                )

                return result

        except Exception as e:
            self.logger.error(f"Failed to discover native libraries: {e}")
            return None


def discover_native_libraries(
    apk_path: str,
    extract_strings: bool = True,
    min_string_length: int = 4
) -> Optional[NativeDiscoveryResult]:
    """
    Convenience function to discover native libraries

    Args:
        apk_path: Path to the APK file
        extract_strings: Extract strings from libraries
        min_string_length: Minimum string length

    Returns:
        Optional[NativeDiscoveryResult]: Discovery results or None if failed
    """
    discovery = NativeDiscovery()

    try:
        result = discovery.discover_from_apk(
            apk_path=apk_path,
            extract_strings=extract_strings,
            min_string_length=min_string_length
        )
        return result

    except Exception as e:
        logging.error(f"Native discovery failed: {e}")
        return None

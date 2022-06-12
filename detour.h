/*
							 __  __     _____     ______   ______     __  __     ______
							/\ \/ /    /\  __-.  /\__  _\ /\  __ \   /\ \/\ \   /\  == \
							\ \  _"-.  \ \ \/\ \ \/_/\ \/ \ \ \/\ \  \ \ \_\ \  \ \  __<
							 \ \_\ \_\  \ \____-    \ \_\  \ \_____\  \ \_____\  \ \_\ \_\
							  \/_/\/_/   \/____/     \/_/   \/_____/   \/_____/   \/_/ /_/
									 simple kernel detour library made by Tuple ©
*/

#ifndef DISABLE_INCLUDES
#include <ntifs.h>
#endif

class c_detour
{
private:
	// unknowncheats.me/forum/2310525-post10.html
	auto wrom( void *src, void *dst, const size_t size ) -> bool
	{
		const auto mdl = IoAllocateMdl( src, size, 0, 0, 0 );

		if ( !mdl )
		{
			return false;
		}

		MmProbeAndLockPages( mdl, KernelMode, IoReadAccess );

		auto map = MmMapLockedPagesSpecifyCache( 
			mdl, KernelMode, MmNonCached, 0, 0, NormalPagePriority );

		if ( !map )
		{
			MmUnmapLockedPages( map, mdl );
			MmUnlockPages( mdl );
			IoFreeMdl( mdl );
			return false;
		}

		MmProtectMdlSystemAddress( mdl, PAGE_READWRITE );

		memcpy( map, dst, size );

		MmUnmapLockedPages( map, mdl );
		MmUnlockPages( mdl );
		IoFreeMdl( mdl );

		return true;
	}

	void *src = nullptr;												// our hooked function address
	void *dst = nullptr;												// our handler address
	unsigned char org[38] = { 0x99 };									// original bytes for uninstall
	bool enabled = false;												// for toggling

public:

	c_detour( void *src, void *dst )									// class constructor
		: src( src ), dst( dst ) { }									// src = function address that gets hooked, dst = our handler

	c_detour( ) {}														// default class constructor

	auto install( ) -> bool												// install function that overwrites function code
	{
		memcpy( this->org, this->src, 38 );								// saves stolen bytes in our variable "org"

		unsigned char jmp_code[] =										// pretty sure this is flagged by anything better then battleye
		{
			0x48, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rdx, 00 00 00 00 00 00 00 00 ; clear rdx register
			0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rcx, 00 00 00 00 00 00 00 00 ; clear rcx register
			0x48, 0x01, 0xd1,											// add rcx, rdx						; set rcx with our handler addres
			0x48, 0x29, 0xca,											// sub rdx, rcx						; clear rdx register from old address
			0xff, 0xe1,													// jmp rcx							; jump to our handler address
			0x48, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00	// mov rcx, 00 00 00 00 00 00 00 00 ; clear rcx register
		};

		memcpy( ( void * )( jmp_code + 2 ), ( uintptr_t * )&dst, 8 );	// set the rdx address to our handler address  

		return this->wrom( this->src, jmp_code, 38 );					// write that shellcode in the rom section
	}

	auto uninstall( ) -> bool											// uninstall function, restore all stolen bytes
	{
		if ( org[0] != 0x99 )
		{
			return this->wrom( this->src, this->org, 38 );					// write back the saved bytes
		}

		return false;
	}

	auto toggle( ) -> bool												// a small wrapper arround uninstall and install
	{
		if ( !this->src || !this->dst )									// check if the addresses are bad to avoid bluescreening
		{
			return false;												// return false if those are invalid
		}

		this->enabled = !this->enabled;									// if its true then its false, if its false then its true

		if ( this->enabled )											// check if its enabled after toggling
		{
			return this->install( );									// if enabled is true then we install
		}

		return this->uninstall( );										// this is like an else if its not enabled then it uninstalls
	}
};
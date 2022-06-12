#include "imports.h"

auto ke_attach_process_hk( PRKPROCESS process ) -> void
{
	DbgPrintEx( 0, 0, "ke_attach_process_hk called" );
}

auto DriverEntry( ) -> NTSTATUS
{					
	const auto ntoskrnl = utils::get_kernel_module( "ntoskrnl.exe" );

	auto ke_attach_process = c_detour( utils::get_kernel_export < void * >( ntoskrnl, "KeAttachProcess" ), &ke_attach_process_hk );

	ke_attach_process.install( ); // hooks function

	ke_attach_process.uninstall( ); // unhooks function

	ke_attach_process.toggle( ); // just a basic switch to install/uninstall 

	return STATUS_SUCCESS;
}
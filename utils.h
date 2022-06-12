namespace utils
{
    auto get_system_information( SYSTEM_INFORMATION_CLASS information_class ) -> void *
    {
        unsigned long size = 32;
        char buffer[32];

        ZwQuerySystemInformation( information_class, buffer, size, &size );

        void *info = ExAllocatePoolZero( NonPagedPool, size, 'hjjd' );

        if ( !info )
            return nullptr;

        if ( !NT_SUCCESS( ZwQuerySystemInformation( information_class, info, size, &size ) ) )
        {
            ExFreePool( info );
            return nullptr;
        }

        return info;
    }

    auto get_kernel_module( const char *name ) -> uintptr_t
    {
        const auto to_lower = []( char *string ) -> const char *
        {
            for ( char *pointer = string; *pointer != '\0'; ++pointer )
            {
                *pointer = ( char )( short )tolower( *pointer );
            }

            return string;
        };

        const PRTL_PROCESS_MODULES info = ( PRTL_PROCESS_MODULES )get_system_information( system_module_information );

        if ( !info )
        {
            return 0;
        }

        for ( size_t i = 0; i < info->number_of_modules; ++i )
        {
            const auto &mod = info->modules[i];

            if ( strcmp( to_lower( ( char * )mod.full_path_name + mod.offset_to_file_name ), name ) == 0 )
            {
                const void *address = mod.image_base;
                ExFreePool( info );
               
                return reinterpret_cast< uintptr_t > ( address );
            }
        }

        ExFreePool( info );

        return 0;
    }

    template <typename t>
    auto get_kernel_export( const uintptr_t base, const char* name ) -> t
    {
        return reinterpret_cast< t >( RtlFindExportedRoutineByName( reinterpret_cast<void*> ( base ), name ) );
    }
}
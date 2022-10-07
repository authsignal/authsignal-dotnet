using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

#if !ISEXTERNALINIT_DISABLE
#nullable enable
#pragma warning disable

namespace System.Runtime.CompilerServices
{
    /// <summary>
    ///     Reserved to be used by the compiler for tracking metadata.
    ///     This class should not be used by developers in source code.
    /// </summary>
    /// <remarks>
    ///     This definition is provided by the <i>IsExternalInit</i> NuGet package
    ///     (https://www.nuget.org/packages/IsExternalInit).
    ///     Please see https://github.com/manuelroemer/IsExternalInit for more information.
    /// </remarks>
#if !ISEXTERNALINIT_INCLUDE_IN_CODE_COVERAGE
    [ExcludeFromCodeCoverage]
    [DebuggerNonUserCode]
#endif
    internal static class IsExternalInit
    {
    }
}

#pragma warning restore
#nullable restore
#endif // ISEXTERNALINIT_DISABLE
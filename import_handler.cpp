#include "includes.h"

bool ResolveImports(class SymbolLoader* loader)
{
	if (!loader)
	{
		return false;
	}

	if (!loader->IsReady())
	{
		return false;
	}

	SymbolParser parser;

	if (!parser.Initialize(loader))
	{
		return false;
	}

	if (!parser.GetNTSymbolAddress(_FUNC_(LdrpHeap)))					return false;
	if (!parser.GetNTSymbolAddress(_FUNC_(RtlAllocateHeap)))			return false;
	if (!parser.GetNTSymbolAddress(_FUNC_(RtlFreeHeap)))				return false;
	if (!parser.GetNTSymbolAddress(_FUNC_(RtlZeroMemory)))				return false;
	if (!parser.GetNTSymbolAddress(_FUNC_(LdrGetProcedureAddress)))		return false;
	if (!parser.GetNTSymbolAddress(_FUNC_(RtlCreateHeap)))				return false;
	if (!parser.GetNTSymbolAddress(_FUNC_(LdrLoadDll)))					return false;

	return true;
}
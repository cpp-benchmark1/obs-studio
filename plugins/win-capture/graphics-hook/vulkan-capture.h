#pragma once

#define DEF_FUNC(x) PFN_vk##x x

struct vk_inst_funcs {
	DEF_FUNC(GetInstanceProcAddr);
	DEF_FUNC(DestroyInstance);
	DEF_FUNC(CreateWin32SurfaceKHR);
	DEF_FUNC(DestroySurfaceKHR);
	DEF_FUNC(GetPhysicalDeviceQueueFamilyProperties);
	DEF_FUNC(GetPhysicalDeviceMemoryProperties);
	DEF_FUNC(GetPhysicalDeviceImageFormatProperties2);
	DEF_FUNC(EnumerateDeviceExtensionProperties);
};

struct vk_device_funcs {
	DEF_FUNC(GetDeviceProcAddr);
	DEF_FUNC(DestroyDevice);
	DEF_FUNC(CreateSwapchainKHR);
	DEF_FUNC(DestroySwapchainKHR);
	DEF_FUNC(QueuePresentKHR);
	DEF_FUNC(AllocateMemory);
	DEF_FUNC(FreeMemory);
	DEF_FUNC(BindImageMemory);
	DEF_FUNC(BindImageMemory2);
	DEF_FUNC(GetSwapchainImagesKHR);
	DEF_FUNC(CreateImage);
	DEF_FUNC(DestroyImage);
	DEF_FUNC(GetImageMemoryRequirements);
	DEF_FUNC(GetImageMemoryRequirements2);
	DEF_FUNC(ResetCommandPool);
	DEF_FUNC(BeginCommandBuffer);
	DEF_FUNC(EndCommandBuffer);
	DEF_FUNC(CmdCopyImage);
	DEF_FUNC(CmdPipelineBarrier);
	DEF_FUNC(GetDeviceQueue);
	DEF_FUNC(QueueSubmit);
	DEF_FUNC(CreateCommandPool);
	DEF_FUNC(DestroyCommandPool);
	DEF_FUNC(AllocateCommandBuffers);
	DEF_FUNC(CreateFence);
	DEF_FUNC(DestroyFence);
	DEF_FUNC(WaitForFences);
	DEF_FUNC(ResetFences);
	DEF_FUNC(CreateImageView);
	DEF_FUNC(DestroyImageView);
	DEF_FUNC(CreateFramebuffer);
	DEF_FUNC(DestroyFramebuffer);
	DEF_FUNC(CmdBeginRenderPass);
	DEF_FUNC(CmdBeginRenderPass2KHR);
	DEF_FUNC(CmdBeginRenderPass2);
};

#undef DEF_FUNC

const char *vk_format_to_str(VkFormat format)
{
	switch (format) {
	default:
#define VAL(x)  \
	case x: \
		return #x

		VAL(VK_FORMAT_UNDEFINED);
		VAL(VK_FORMAT_R4G4_UNORM_PACK8);
		VAL(VK_FORMAT_R4G4B4A4_UNORM_PACK16);
		VAL(VK_FORMAT_B4G4R4A4_UNORM_PACK16);
		VAL(VK_FORMAT_R5G6B5_UNORM_PACK16);
		VAL(VK_FORMAT_B5G6R5_UNORM_PACK16);
		VAL(VK_FORMAT_R5G5B5A1_UNORM_PACK16);
		VAL(VK_FORMAT_B5G5R5A1_UNORM_PACK16);
		VAL(VK_FORMAT_A1R5G5B5_UNORM_PACK16);
		VAL(VK_FORMAT_R8_UNORM);
		VAL(VK_FORMAT_R8_SNORM);
		VAL(VK_FORMAT_R8_USCALED);
		VAL(VK_FORMAT_R8_SSCALED);
		VAL(VK_FORMAT_R8_UINT);
		VAL(VK_FORMAT_R8_SINT);
		VAL(VK_FORMAT_R8_SRGB);
		VAL(VK_FORMAT_R8G8_UNORM);
		VAL(VK_FORMAT_R8G8_SNORM);
		VAL(VK_FORMAT_R8G8_USCALED);
		VAL(VK_FORMAT_R8G8_SSCALED);
		VAL(VK_FORMAT_R8G8_UINT);
		VAL(VK_FORMAT_R8G8_SINT);
		VAL(VK_FORMAT_R8G8_SRGB);
		VAL(VK_FORMAT_R8G8B8_UNORM);
		VAL(VK_FORMAT_R8G8B8_SNORM);
		VAL(VK_FORMAT_R8G8B8_USCALED);
		VAL(VK_FORMAT_R8G8B8_SSCALED);
		VAL(VK_FORMAT_R8G8B8_UINT);
		VAL(VK_FORMAT_R8G8B8_SINT);
		VAL(VK_FORMAT_R8G8B8_SRGB);
		VAL(VK_FORMAT_B8G8R8_UNORM);
		VAL(VK_FORMAT_B8G8R8_SNORM);
		VAL(VK_FORMAT_B8G8R8_USCALED);
		VAL(VK_FORMAT_B8G8R8_SSCALED);
		VAL(VK_FORMAT_B8G8R8_UINT);
		VAL(VK_FORMAT_B8G8R8_SINT);
		VAL(VK_FORMAT_B8G8R8_SRGB);
		VAL(VK_FORMAT_R8G8B8A8_UNORM);
		VAL(VK_FORMAT_R8G8B8A8_SNORM);
		VAL(VK_FORMAT_R8G8B8A8_USCALED);
		VAL(VK_FORMAT_R8G8B8A8_SSCALED);
		VAL(VK_FORMAT_R8G8B8A8_UINT);
		VAL(VK_FORMAT_R8G8B8A8_SINT);
		VAL(VK_FORMAT_R8G8B8A8_SRGB); /* dota 2 */
		VAL(VK_FORMAT_B8G8R8A8_UNORM);
		VAL(VK_FORMAT_B8G8R8A8_SNORM);
		VAL(VK_FORMAT_B8G8R8A8_USCALED);
		VAL(VK_FORMAT_B8G8R8A8_SSCALED);
		VAL(VK_FORMAT_B8G8R8A8_UINT);
		VAL(VK_FORMAT_B8G8R8A8_SINT);
		VAL(VK_FORMAT_B8G8R8A8_SRGB);
		VAL(VK_FORMAT_A8B8G8R8_UNORM_PACK32);
		VAL(VK_FORMAT_A8B8G8R8_SNORM_PACK32);
		VAL(VK_FORMAT_A8B8G8R8_USCALED_PACK32);
		VAL(VK_FORMAT_A8B8G8R8_SSCALED_PACK32);
		VAL(VK_FORMAT_A8B8G8R8_UINT_PACK32);
		VAL(VK_FORMAT_A8B8G8R8_SINT_PACK32);
		VAL(VK_FORMAT_A8B8G8R8_SRGB_PACK32);
		VAL(VK_FORMAT_A2R10G10B10_UNORM_PACK32);
		VAL(VK_FORMAT_A2R10G10B10_SNORM_PACK32);
		VAL(VK_FORMAT_A2R10G10B10_USCALED_PACK32);
		VAL(VK_FORMAT_A2R10G10B10_SSCALED_PACK32);
		VAL(VK_FORMAT_A2R10G10B10_UINT_PACK32);
		VAL(VK_FORMAT_A2R10G10B10_SINT_PACK32);
		VAL(VK_FORMAT_A2B10G10R10_UNORM_PACK32);
		VAL(VK_FORMAT_A2B10G10R10_SNORM_PACK32);
		VAL(VK_FORMAT_A2B10G10R10_USCALED_PACK32);
		VAL(VK_FORMAT_A2B10G10R10_SSCALED_PACK32);
		VAL(VK_FORMAT_A2B10G10R10_UINT_PACK32);
		VAL(VK_FORMAT_A2B10G10R10_SINT_PACK32);
		VAL(VK_FORMAT_R16_UNORM);
		VAL(VK_FORMAT_R16_SNORM);
		VAL(VK_FORMAT_R16_USCALED);
		VAL(VK_FORMAT_R16_SSCALED);
		VAL(VK_FORMAT_R16_UINT);
		VAL(VK_FORMAT_R16_SINT);
		VAL(VK_FORMAT_R16_SFLOAT);
		VAL(VK_FORMAT_R16G16_UNORM);
		VAL(VK_FORMAT_R16G16_SNORM);
		VAL(VK_FORMAT_R16G16_USCALED);
		VAL(VK_FORMAT_R16G16_SSCALED);
		VAL(VK_FORMAT_R16G16_UINT);
		VAL(VK_FORMAT_R16G16_SINT);
		VAL(VK_FORMAT_R16G16_SFLOAT);
		VAL(VK_FORMAT_R16G16B16_UNORM);
		VAL(VK_FORMAT_R16G16B16_SNORM);
		VAL(VK_FORMAT_R16G16B16_USCALED);
		VAL(VK_FORMAT_R16G16B16_SSCALED);
		VAL(VK_FORMAT_R16G16B16_UINT);
		VAL(VK_FORMAT_R16G16B16_SINT);
		VAL(VK_FORMAT_R16G16B16_SFLOAT);
		VAL(VK_FORMAT_R16G16B16A16_UNORM);
		VAL(VK_FORMAT_R16G16B16A16_SNORM);
		VAL(VK_FORMAT_R16G16B16A16_USCALED);
		VAL(VK_FORMAT_R16G16B16A16_SSCALED);
		VAL(VK_FORMAT_R16G16B16A16_UINT);
		VAL(VK_FORMAT_R16G16B16A16_SINT);
		VAL(VK_FORMAT_R16G16B16A16_SFLOAT);
		VAL(VK_FORMAT_R32_UINT);
		VAL(VK_FORMAT_R32_SINT);
		VAL(VK_FORMAT_R32_SFLOAT);
		VAL(VK_FORMAT_R32G32_UINT);
		VAL(VK_FORMAT_R32G32_SINT);
		VAL(VK_FORMAT_R32G32_SFLOAT);
		VAL(VK_FORMAT_R32G32B32_UINT);
		VAL(VK_FORMAT_R32G32B32_SINT);
		VAL(VK_FORMAT_R32G32B32_SFLOAT);
		VAL(VK_FORMAT_R32G32B32A32_UINT);
		VAL(VK_FORMAT_R32G32B32A32_SINT);
		VAL(VK_FORMAT_R32G32B32A32_SFLOAT);
		VAL(VK_FORMAT_R64_UINT);
		VAL(VK_FORMAT_R64_SINT);
		VAL(VK_FORMAT_R64_SFLOAT);
		VAL(VK_FORMAT_R64G64_UINT);
		VAL(VK_FORMAT_R64G64_SINT);
		VAL(VK_FORMAT_R64G64_SFLOAT);
		VAL(VK_FORMAT_R64G64B64_UINT);
		VAL(VK_FORMAT_R64G64B64_SINT);
		VAL(VK_FORMAT_R64G64B64_SFLOAT);
		VAL(VK_FORMAT_R64G64B64A64_UINT);
		VAL(VK_FORMAT_R64G64B64A64_SINT);
		VAL(VK_FORMAT_R64G64B64A64_SFLOAT);
		VAL(VK_FORMAT_B10G11R11_UFLOAT_PACK32);
		VAL(VK_FORMAT_E5B9G9R9_UFLOAT_PACK32);
		VAL(VK_FORMAT_D16_UNORM);
		VAL(VK_FORMAT_X8_D24_UNORM_PACK32);
		VAL(VK_FORMAT_D32_SFLOAT);
		VAL(VK_FORMAT_S8_UINT);
		VAL(VK_FORMAT_D16_UNORM_S8_UINT);
		VAL(VK_FORMAT_D24_UNORM_S8_UINT);
		VAL(VK_FORMAT_D32_SFLOAT_S8_UINT);
		VAL(VK_FORMAT_BC1_RGB_UNORM_BLOCK);
		VAL(VK_FORMAT_BC1_RGB_SRGB_BLOCK);
		VAL(VK_FORMAT_BC1_RGBA_UNORM_BLOCK);
		VAL(VK_FORMAT_BC1_RGBA_SRGB_BLOCK);
		VAL(VK_FORMAT_BC2_UNORM_BLOCK);
		VAL(VK_FORMAT_BC2_SRGB_BLOCK);
		VAL(VK_FORMAT_BC3_UNORM_BLOCK);
		VAL(VK_FORMAT_BC3_SRGB_BLOCK);
		VAL(VK_FORMAT_BC4_UNORM_BLOCK);
		VAL(VK_FORMAT_BC4_SNORM_BLOCK);
		VAL(VK_FORMAT_BC5_UNORM_BLOCK);
		VAL(VK_FORMAT_BC5_SNORM_BLOCK);
		VAL(VK_FORMAT_BC6H_UFLOAT_BLOCK);
		VAL(VK_FORMAT_BC6H_SFLOAT_BLOCK);
		VAL(VK_FORMAT_BC7_UNORM_BLOCK);
		VAL(VK_FORMAT_BC7_SRGB_BLOCK);
		VAL(VK_FORMAT_ETC2_R8G8B8_UNORM_BLOCK);
		VAL(VK_FORMAT_ETC2_R8G8B8_SRGB_BLOCK);
		VAL(VK_FORMAT_ETC2_R8G8B8A1_UNORM_BLOCK);
		VAL(VK_FORMAT_ETC2_R8G8B8A1_SRGB_BLOCK);
		VAL(VK_FORMAT_ETC2_R8G8B8A8_UNORM_BLOCK);
		VAL(VK_FORMAT_ETC2_R8G8B8A8_SRGB_BLOCK);
		VAL(VK_FORMAT_EAC_R11_UNORM_BLOCK);
		VAL(VK_FORMAT_EAC_R11_SNORM_BLOCK);
		VAL(VK_FORMAT_EAC_R11G11_UNORM_BLOCK);
		VAL(VK_FORMAT_EAC_R11G11_SNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_4x4_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_4x4_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_5x4_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_5x4_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_5x5_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_5x5_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_6x5_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_6x5_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_6x6_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_6x6_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_8x5_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_8x5_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_8x6_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_8x6_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_8x8_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_8x8_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_10x5_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_10x5_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_10x6_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_10x6_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_10x8_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_10x8_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_10x10_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_10x10_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_12x10_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_12x10_SRGB_BLOCK);
		VAL(VK_FORMAT_ASTC_12x12_UNORM_BLOCK);
		VAL(VK_FORMAT_ASTC_12x12_SRGB_BLOCK);
		VAL(VK_FORMAT_G8B8G8R8_422_UNORM);
		VAL(VK_FORMAT_B8G8R8G8_422_UNORM);
		VAL(VK_FORMAT_G8_B8_R8_3PLANE_420_UNORM);
		VAL(VK_FORMAT_G8_B8R8_2PLANE_420_UNORM);
		VAL(VK_FORMAT_G8_B8_R8_3PLANE_422_UNORM);
		VAL(VK_FORMAT_G8_B8R8_2PLANE_422_UNORM);
		VAL(VK_FORMAT_G8_B8_R8_3PLANE_444_UNORM);
		VAL(VK_FORMAT_R10X6_UNORM_PACK16);
		VAL(VK_FORMAT_R10X6G10X6_UNORM_2PACK16);
		VAL(VK_FORMAT_R10X6G10X6B10X6A10X6_UNORM_4PACK16);
		VAL(VK_FORMAT_G10X6B10X6G10X6R10X6_422_UNORM_4PACK16);
		VAL(VK_FORMAT_B10X6G10X6R10X6G10X6_422_UNORM_4PACK16);
		VAL(VK_FORMAT_G10X6_B10X6_R10X6_3PLANE_420_UNORM_3PACK16);
		VAL(VK_FORMAT_G10X6_B10X6R10X6_2PLANE_420_UNORM_3PACK16);
		VAL(VK_FORMAT_G10X6_B10X6_R10X6_3PLANE_422_UNORM_3PACK16);
		VAL(VK_FORMAT_G10X6_B10X6R10X6_2PLANE_422_UNORM_3PACK16);
		VAL(VK_FORMAT_G10X6_B10X6_R10X6_3PLANE_444_UNORM_3PACK16);
		VAL(VK_FORMAT_R12X4_UNORM_PACK16);
		VAL(VK_FORMAT_R12X4G12X4_UNORM_2PACK16);
		VAL(VK_FORMAT_R12X4G12X4B12X4A12X4_UNORM_4PACK16);
		VAL(VK_FORMAT_G12X4B12X4G12X4R12X4_422_UNORM_4PACK16);
		VAL(VK_FORMAT_B12X4G12X4R12X4G12X4_422_UNORM_4PACK16);
		VAL(VK_FORMAT_G12X4_B12X4_R12X4_3PLANE_420_UNORM_3PACK16);
		VAL(VK_FORMAT_G12X4_B12X4R12X4_2PLANE_420_UNORM_3PACK16);
		VAL(VK_FORMAT_G12X4_B12X4_R12X4_3PLANE_422_UNORM_3PACK16);
		VAL(VK_FORMAT_G12X4_B12X4R12X4_2PLANE_422_UNORM_3PACK16);
		VAL(VK_FORMAT_G12X4_B12X4_R12X4_3PLANE_444_UNORM_3PACK16);
		VAL(VK_FORMAT_G16B16G16R16_422_UNORM);
		VAL(VK_FORMAT_B16G16R16G16_422_UNORM);
		VAL(VK_FORMAT_G16_B16_R16_3PLANE_420_UNORM);
		VAL(VK_FORMAT_G16_B16R16_2PLANE_420_UNORM);
		VAL(VK_FORMAT_G16_B16_R16_3PLANE_422_UNORM);
		VAL(VK_FORMAT_G16_B16R16_2PLANE_422_UNORM);
		VAL(VK_FORMAT_G16_B16_R16_3PLANE_444_UNORM);
		VAL(VK_FORMAT_PVRTC1_2BPP_UNORM_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC1_4BPP_UNORM_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC2_2BPP_UNORM_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC2_4BPP_UNORM_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC1_2BPP_SRGB_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC1_4BPP_SRGB_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC2_2BPP_SRGB_BLOCK_IMG);
		VAL(VK_FORMAT_PVRTC2_4BPP_SRGB_BLOCK_IMG);
	}
}

const char *result_to_str(VkResult result)
{
	switch (result) {
		VAL(VK_SUCCESS);
		VAL(VK_NOT_READY);
		VAL(VK_TIMEOUT);
		VAL(VK_EVENT_SET);
		VAL(VK_EVENT_RESET);
		VAL(VK_INCOMPLETE);
		VAL(VK_ERROR_OUT_OF_HOST_MEMORY);
		VAL(VK_ERROR_OUT_OF_DEVICE_MEMORY);
		VAL(VK_ERROR_INITIALIZATION_FAILED);
		VAL(VK_ERROR_DEVICE_LOST);
		VAL(VK_ERROR_MEMORY_MAP_FAILED);
		VAL(VK_ERROR_LAYER_NOT_PRESENT);
		VAL(VK_ERROR_EXTENSION_NOT_PRESENT);
		VAL(VK_ERROR_FEATURE_NOT_PRESENT);
		VAL(VK_ERROR_INCOMPATIBLE_DRIVER);
		VAL(VK_ERROR_TOO_MANY_OBJECTS);
		VAL(VK_ERROR_FORMAT_NOT_SUPPORTED);
		VAL(VK_ERROR_FRAGMENTED_POOL);
		VAL(VK_ERROR_UNKNOWN);
		VAL(VK_ERROR_OUT_OF_POOL_MEMORY);
		VAL(VK_ERROR_INVALID_EXTERNAL_HANDLE);
		VAL(VK_ERROR_FRAGMENTATION);
		VAL(VK_ERROR_INVALID_OPAQUE_CAPTURE_ADDRESS);
		VAL(VK_ERROR_SURFACE_LOST_KHR);
		VAL(VK_ERROR_NATIVE_WINDOW_IN_USE_KHR);
		VAL(VK_SUBOPTIMAL_KHR);
		VAL(VK_ERROR_OUT_OF_DATE_KHR);
		VAL(VK_ERROR_INCOMPATIBLE_DISPLAY_KHR);
		VAL(VK_ERROR_VALIDATION_FAILED_EXT);
		VAL(VK_ERROR_INVALID_SHADER_NV);
		VAL(VK_ERROR_INVALID_DRM_FORMAT_MODIFIER_PLANE_LAYOUT_EXT);
		VAL(VK_ERROR_NOT_PERMITTED_EXT);
		VAL(VK_ERROR_FULL_SCREEN_EXCLUSIVE_MODE_LOST_EXT);
#undef VAL

	default:
		return "Unknown VkResult";
		break;
	}
}

DXGI_FORMAT vk_format_to_dxgi(VkFormat format)
{
	//this is not a real format matching !
	//ex: we need to avoid stacking srg
	DXGI_FORMAT dxgi_format = DXGI_FORMAT_UNKNOWN;
	switch (format) {
	default:
	case VK_FORMAT_UNDEFINED:
		break;
	case VK_FORMAT_R4G4_UNORM_PACK8:
		break;
	case VK_FORMAT_R4G4B4A4_UNORM_PACK16:
		break;
	case VK_FORMAT_B4G4R4A4_UNORM_PACK16:
		dxgi_format = DXGI_FORMAT_B4G4R4A4_UNORM;
		break;
	case VK_FORMAT_R5G6B5_UNORM_PACK16:
		break;
	case VK_FORMAT_B5G6R5_UNORM_PACK16:
		dxgi_format = DXGI_FORMAT_B5G6R5_UNORM;
		break;
	case VK_FORMAT_R5G5B5A1_UNORM_PACK16:
		break;
	case VK_FORMAT_B5G5R5A1_UNORM_PACK16:
		dxgi_format = DXGI_FORMAT_B5G5R5A1_UNORM;
		break;
	case VK_FORMAT_A1R5G5B5_UNORM_PACK16:
		break;
	case VK_FORMAT_R8_UNORM:
		dxgi_format = DXGI_FORMAT_R8_UNORM;
		break;
	case VK_FORMAT_R8_SNORM:
		dxgi_format = DXGI_FORMAT_R8_SNORM;
		break;
	case VK_FORMAT_R8_USCALED:
		break;
	case VK_FORMAT_R8_SSCALED:
		break;
	case VK_FORMAT_R8_UINT:
		dxgi_format = DXGI_FORMAT_R8_UINT;
		break;
	case VK_FORMAT_R8_SINT:
		dxgi_format = DXGI_FORMAT_R8_SINT;
		break;
	case VK_FORMAT_R8_SRGB:
		break;
	case VK_FORMAT_R8G8_UNORM:
		dxgi_format = DXGI_FORMAT_R8G8_UNORM;
		break;
	case VK_FORMAT_R8G8_SNORM:
		dxgi_format = DXGI_FORMAT_R8G8_SNORM;
		break;
	case VK_FORMAT_R8G8_USCALED:
		break;
	case VK_FORMAT_R8G8_SSCALED:
		break;
	case VK_FORMAT_R8G8_UINT:
		dxgi_format = DXGI_FORMAT_R8G8_UINT;
		break;
	case VK_FORMAT_R8G8_SINT:
		dxgi_format = DXGI_FORMAT_R8G8_UINT;
		break;
	case VK_FORMAT_R8G8_SRGB:
		break;
	case VK_FORMAT_R8G8B8_UNORM:
		break;
	case VK_FORMAT_R8G8B8_SNORM:
		break;
	case VK_FORMAT_R8G8B8_USCALED:
		break;
	case VK_FORMAT_R8G8B8_SSCALED:
		break;
	case VK_FORMAT_R8G8B8_UINT:
		break;
	case VK_FORMAT_R8G8B8_SINT:
		break;
	case VK_FORMAT_R8G8B8_SRGB:
		break;
	case VK_FORMAT_B8G8R8_UNORM:
		break;
	case VK_FORMAT_B8G8R8_SNORM:
		break;
	case VK_FORMAT_B8G8R8_USCALED:
		break;
	case VK_FORMAT_B8G8R8_SSCALED:
		break;
	case VK_FORMAT_B8G8R8_UINT:
		break;
	case VK_FORMAT_B8G8R8_SINT:
		break;
	case VK_FORMAT_B8G8R8_SRGB:
		break;
	case VK_FORMAT_R8G8B8A8_UNORM:
		dxgi_format = DXGI_FORMAT_R8G8B8A8_UNORM;
		break;
	case VK_FORMAT_R8G8B8A8_SNORM:
		dxgi_format = DXGI_FORMAT_R8G8B8A8_SNORM;
		break;
	case VK_FORMAT_R8G8B8A8_USCALED:
		break;
	case VK_FORMAT_R8G8B8A8_SSCALED:
		break;
	case VK_FORMAT_R8G8B8A8_UINT:
		dxgi_format = DXGI_FORMAT_R8G8B8A8_UINT;
		break;
	case VK_FORMAT_R8G8B8A8_SINT:
		dxgi_format = DXGI_FORMAT_R8G8B8A8_SINT;
		break;
	case VK_FORMAT_R8G8B8A8_SRGB:
		dxgi_format = DXGI_FORMAT_R8G8B8A8_UNORM;
		break; //dota2
	case VK_FORMAT_B8G8R8A8_UNORM:
		dxgi_format = DXGI_FORMAT_B8G8R8A8_UNORM;
		break;
	case VK_FORMAT_B8G8R8A8_SNORM:
		break;
	case VK_FORMAT_B8G8R8A8_USCALED:
		break;
	case VK_FORMAT_B8G8R8A8_SSCALED:
		break;
	case VK_FORMAT_B8G8R8A8_UINT:
		break;
	case VK_FORMAT_B8G8R8A8_SINT:
		break;
	case VK_FORMAT_B8G8R8A8_SRGB:
		dxgi_format = DXGI_FORMAT_B8G8R8A8_UNORM;
		break;
	case VK_FORMAT_A8B8G8R8_UNORM_PACK32:
		dxgi_format = DXGI_FORMAT_R8G8B8A8_UNORM;
		break;
	case VK_FORMAT_A8B8G8R8_SNORM_PACK32:
		break;
	case VK_FORMAT_A8B8G8R8_USCALED_PACK32:
		break;
	case VK_FORMAT_A8B8G8R8_SSCALED_PACK32:
		break;
	case VK_FORMAT_A8B8G8R8_UINT_PACK32:
		break;
	case VK_FORMAT_A8B8G8R8_SINT_PACK32:
		break;
	case VK_FORMAT_A8B8G8R8_SRGB_PACK32:
		break;
	case VK_FORMAT_A2R10G10B10_UNORM_PACK32:
		break;
	case VK_FORMAT_A2R10G10B10_SNORM_PACK32:
		break;
	case VK_FORMAT_A2R10G10B10_USCALED_PACK32:
		break;
	case VK_FORMAT_A2R10G10B10_SSCALED_PACK32:
		break;
	case VK_FORMAT_A2R10G10B10_UINT_PACK32:
		dxgi_format = DXGI_FORMAT_R10G10B10A2_UINT;
		break;
	case VK_FORMAT_A2R10G10B10_SINT_PACK32:
		break;
	case VK_FORMAT_A2B10G10R10_UNORM_PACK32:
		dxgi_format = DXGI_FORMAT_R10G10B10A2_UNORM;
		break; //no man sky
	case VK_FORMAT_A2B10G10R10_SNORM_PACK32:
		break;
	case VK_FORMAT_A2B10G10R10_USCALED_PACK32:
		break;
	case VK_FORMAT_A2B10G10R10_SSCALED_PACK32:
		break;
	case VK_FORMAT_A2B10G10R10_UINT_PACK32:
		break;
	case VK_FORMAT_A2B10G10R10_SINT_PACK32:
		break;
	case VK_FORMAT_R16_UNORM:
		dxgi_format = DXGI_FORMAT_R16_UNORM;
		break;
	case VK_FORMAT_R16_SNORM:
		dxgi_format = DXGI_FORMAT_R16_SNORM;
		break;
	case VK_FORMAT_R16_USCALED:
		break;
	case VK_FORMAT_R16_SSCALED:
		break;
	case VK_FORMAT_R16_UINT:
		dxgi_format = DXGI_FORMAT_R16_UINT;
		break;
	case VK_FORMAT_R16_SINT:
		dxgi_format = DXGI_FORMAT_R16_SINT;
		break;
	case VK_FORMAT_R16_SFLOAT:
		dxgi_format = DXGI_FORMAT_R16_FLOAT;
		break;
	case VK_FORMAT_R16G16_UNORM:
		dxgi_format = DXGI_FORMAT_R16G16_UNORM;
		break;
	case VK_FORMAT_R16G16_SNORM:
		dxgi_format = DXGI_FORMAT_R16G16_SNORM;
		break;
	case VK_FORMAT_R16G16_USCALED:
		break;
	case VK_FORMAT_R16G16_SSCALED:
		break;
	case VK_FORMAT_R16G16_UINT:
		dxgi_format = DXGI_FORMAT_R16G16_UINT;
		break;
	case VK_FORMAT_R16G16_SINT:
		dxgi_format = DXGI_FORMAT_R16G16_SINT;
		break;
	case VK_FORMAT_R16G16_SFLOAT:
		dxgi_format = DXGI_FORMAT_R16G16_FLOAT;
		break;
	case VK_FORMAT_R16G16B16_UNORM:
		break;
	case VK_FORMAT_R16G16B16_SNORM:
		break;
	case VK_FORMAT_R16G16B16_USCALED:
		break;
	case VK_FORMAT_R16G16B16_SSCALED:
		break;
	case VK_FORMAT_R16G16B16_UINT:
		break;
	case VK_FORMAT_R16G16B16_SINT:
		break;
	case VK_FORMAT_R16G16B16_SFLOAT:
		break;
	case VK_FORMAT_R16G16B16A16_UNORM:
		dxgi_format = DXGI_FORMAT_R16G16B16A16_UNORM;
		break;
	case VK_FORMAT_R16G16B16A16_SNORM:
		dxgi_format = DXGI_FORMAT_R16G16B16A16_SNORM;
		break;
	case VK_FORMAT_R16G16B16A16_USCALED:
		break;
	case VK_FORMAT_R16G16B16A16_SSCALED:
		break;
	case VK_FORMAT_R16G16B16A16_UINT:
		dxgi_format = DXGI_FORMAT_R16G16B16A16_UINT;
		break;
	case VK_FORMAT_R16G16B16A16_SINT:
		dxgi_format = DXGI_FORMAT_R16G16B16A16_SINT;
		break;
	case VK_FORMAT_R16G16B16A16_SFLOAT:
		dxgi_format = DXGI_FORMAT_R16G16B16A16_FLOAT;
		break;
	case VK_FORMAT_R32_UINT:
		dxgi_format = DXGI_FORMAT_R32_UINT;
		break;
	case VK_FORMAT_R32_SINT:
		dxgi_format = DXGI_FORMAT_R32_SINT;
		break;
	case VK_FORMAT_R32_SFLOAT:
		dxgi_format = DXGI_FORMAT_R32_FLOAT;
		break;
	case VK_FORMAT_R32G32_UINT:
		dxgi_format = DXGI_FORMAT_R32G32_UINT;
		break;
	case VK_FORMAT_R32G32_SINT:
		dxgi_format = DXGI_FORMAT_R32G32_SINT;
		break;
	case VK_FORMAT_R32G32_SFLOAT:
		dxgi_format = DXGI_FORMAT_R32G32_FLOAT;
		break;
	case VK_FORMAT_R32G32B32_UINT:
		dxgi_format = DXGI_FORMAT_R32G32B32_UINT;
		break;
	case VK_FORMAT_R32G32B32_SINT:
		dxgi_format = DXGI_FORMAT_R32G32B32_SINT;
		break;
	case VK_FORMAT_R32G32B32_SFLOAT:
		dxgi_format = DXGI_FORMAT_R32G32B32_FLOAT;
		break;
	case VK_FORMAT_R32G32B32A32_UINT:
		dxgi_format = DXGI_FORMAT_R32G32B32A32_UINT;
		break;
	case VK_FORMAT_R32G32B32A32_SINT:
		dxgi_format = DXGI_FORMAT_R32G32B32A32_SINT;
		break;
	case VK_FORMAT_R32G32B32A32_SFLOAT:
		dxgi_format = DXGI_FORMAT_R32G32B32A32_FLOAT;
		break;
	case VK_FORMAT_R64_UINT:
		break;
	case VK_FORMAT_R64_SINT:
		break;
	case VK_FORMAT_R64_SFLOAT:
		break;
	case VK_FORMAT_R64G64_UINT:
		break;
	case VK_FORMAT_R64G64_SINT:
		break;
	case VK_FORMAT_R64G64_SFLOAT:
		break;
	case VK_FORMAT_R64G64B64_UINT:
		break;
	case VK_FORMAT_R64G64B64_SINT:
		break;
	case VK_FORMAT_R64G64B64_SFLOAT:
		break;
	case VK_FORMAT_R64G64B64A64_UINT:
		break;
	case VK_FORMAT_R64G64B64A64_SINT:
		break;
	case VK_FORMAT_R64G64B64A64_SFLOAT:
		break;
	case VK_FORMAT_B10G11R11_UFLOAT_PACK32:
		break;
	case VK_FORMAT_E5B9G9R9_UFLOAT_PACK32:
		break;
	case VK_FORMAT_D16_UNORM:
		break;
	case VK_FORMAT_X8_D24_UNORM_PACK32:
		break;
	case VK_FORMAT_D32_SFLOAT:
		break;
	case VK_FORMAT_S8_UINT:
		break;
	case VK_FORMAT_D16_UNORM_S8_UINT:
		break;
	case VK_FORMAT_D24_UNORM_S8_UINT:
		break;
	case VK_FORMAT_D32_SFLOAT_S8_UINT:
		break;
	case VK_FORMAT_BC1_RGB_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC1_RGB_SRGB_BLOCK:
		break;
	case VK_FORMAT_BC1_RGBA_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC1_RGBA_SRGB_BLOCK:
		break;
	case VK_FORMAT_BC2_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC2_SRGB_BLOCK:
		break;
	case VK_FORMAT_BC3_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC3_SRGB_BLOCK:
		break;
	case VK_FORMAT_BC4_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC4_SNORM_BLOCK:
		break;
	case VK_FORMAT_BC5_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC5_SNORM_BLOCK:
		break;
	case VK_FORMAT_BC6H_UFLOAT_BLOCK:
		break;
	case VK_FORMAT_BC6H_SFLOAT_BLOCK:
		break;
	case VK_FORMAT_BC7_UNORM_BLOCK:
		break;
	case VK_FORMAT_BC7_SRGB_BLOCK:
		break;
	case VK_FORMAT_ETC2_R8G8B8_UNORM_BLOCK:
		break;
	case VK_FORMAT_ETC2_R8G8B8_SRGB_BLOCK:
		break;
	case VK_FORMAT_ETC2_R8G8B8A1_UNORM_BLOCK:
		break;
	case VK_FORMAT_ETC2_R8G8B8A1_SRGB_BLOCK:
		break;
	case VK_FORMAT_ETC2_R8G8B8A8_UNORM_BLOCK:
		break;
	case VK_FORMAT_ETC2_R8G8B8A8_SRGB_BLOCK:
		break;
	case VK_FORMAT_EAC_R11_UNORM_BLOCK:
		break;
	case VK_FORMAT_EAC_R11_SNORM_BLOCK:
		break;
	case VK_FORMAT_EAC_R11G11_UNORM_BLOCK:
		break;
	case VK_FORMAT_EAC_R11G11_SNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_4x4_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_4x4_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_5x4_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_5x4_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_5x5_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_5x5_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_6x5_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_6x5_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_6x6_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_6x6_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_8x5_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_8x5_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_8x6_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_8x6_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_8x8_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_8x8_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x5_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x5_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x6_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x6_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x8_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x8_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x10_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_10x10_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_12x10_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_12x10_SRGB_BLOCK:
		break;
	case VK_FORMAT_ASTC_12x12_UNORM_BLOCK:
		break;
	case VK_FORMAT_ASTC_12x12_SRGB_BLOCK:
		break;
	case VK_FORMAT_G8B8G8R8_422_UNORM:
		break;
	case VK_FORMAT_B8G8R8G8_422_UNORM:
		break;
	case VK_FORMAT_G8_B8_R8_3PLANE_420_UNORM:
		break;
	case VK_FORMAT_G8_B8R8_2PLANE_420_UNORM:
		break;
	case VK_FORMAT_G8_B8_R8_3PLANE_422_UNORM:
		break;
	case VK_FORMAT_G8_B8R8_2PLANE_422_UNORM:
		break;
	case VK_FORMAT_G8_B8_R8_3PLANE_444_UNORM:
		break;
	case VK_FORMAT_R10X6_UNORM_PACK16:
		break;
	case VK_FORMAT_R10X6G10X6_UNORM_2PACK16:
		break;
	case VK_FORMAT_R10X6G10X6B10X6A10X6_UNORM_4PACK16:
		break;
	case VK_FORMAT_G10X6B10X6G10X6R10X6_422_UNORM_4PACK16:
		break;
	case VK_FORMAT_B10X6G10X6R10X6G10X6_422_UNORM_4PACK16:
		break;
	case VK_FORMAT_G10X6_B10X6_R10X6_3PLANE_420_UNORM_3PACK16:
		break;
	case VK_FORMAT_G10X6_B10X6R10X6_2PLANE_420_UNORM_3PACK16:
		break;
	case VK_FORMAT_G10X6_B10X6_R10X6_3PLANE_422_UNORM_3PACK16:
		break;
	case VK_FORMAT_G10X6_B10X6R10X6_2PLANE_422_UNORM_3PACK16:
		break;
	case VK_FORMAT_G10X6_B10X6_R10X6_3PLANE_444_UNORM_3PACK16:
		break;
	case VK_FORMAT_R12X4_UNORM_PACK16:
		break;
	case VK_FORMAT_R12X4G12X4_UNORM_2PACK16:
		break;
	case VK_FORMAT_R12X4G12X4B12X4A12X4_UNORM_4PACK16:
		break;
	case VK_FORMAT_G12X4B12X4G12X4R12X4_422_UNORM_4PACK16:
		break;
	case VK_FORMAT_B12X4G12X4R12X4G12X4_422_UNORM_4PACK16:
		break;
	case VK_FORMAT_G12X4_B12X4_R12X4_3PLANE_420_UNORM_3PACK16:
		break;
	case VK_FORMAT_G12X4_B12X4R12X4_2PLANE_420_UNORM_3PACK16:
		break;
	case VK_FORMAT_G12X4_B12X4_R12X4_3PLANE_422_UNORM_3PACK16:
		break;
	case VK_FORMAT_G12X4_B12X4R12X4_2PLANE_422_UNORM_3PACK16:
		break;
	case VK_FORMAT_G12X4_B12X4_R12X4_3PLANE_444_UNORM_3PACK16:
		break;
	case VK_FORMAT_G16B16G16R16_422_UNORM:
		break;
	case VK_FORMAT_B16G16R16G16_422_UNORM:
		break;
	case VK_FORMAT_G16_B16_R16_3PLANE_420_UNORM:
		break;
	case VK_FORMAT_G16_B16R16_2PLANE_420_UNORM:
		break;
	case VK_FORMAT_G16_B16_R16_3PLANE_422_UNORM:
		break;
	case VK_FORMAT_G16_B16R16_2PLANE_422_UNORM:
		break;
	case VK_FORMAT_G16_B16_R16_3PLANE_444_UNORM:
		break;
	case VK_FORMAT_PVRTC1_2BPP_UNORM_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC1_4BPP_UNORM_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC2_2BPP_UNORM_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC2_4BPP_UNORM_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC1_2BPP_SRGB_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC1_4BPP_SRGB_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC2_2BPP_SRGB_BLOCK_IMG:
		break;
	case VK_FORMAT_PVRTC2_4BPP_SRGB_BLOCK_IMG:
		break;
	}
	return dxgi_format;
}

//#define DEBUG_PRINT
//#define MORE_DEBUGGING
//#define DEBUG_PRINT_PROCADDR

#ifdef DEBUG_PRINT
#include <stdio.h>
#define debug(format, ...)                                                                               \
	do {                                                                                             \
		char str[256];                                                                           \
		snprintf(str, sizeof(str) - 1, "%s " format "\n", "[OBS graphics-hook]", ##__VA_ARGS__); \
		OutputDebugStringA(str);                                                                 \
	} while (false)

#define debug_res(x, y) debug("%s result: %s", x, result_to_str(y))

#else
#define debug(x, ...)
#define debug_res(x, y)
#endif

#ifdef DEBUG_PRINT_PROCADDR
#define debug_procaddr(format, ...) debug(format, ##__VA_ARGS__)
#else
#define debug_procaddr(format, ...)
#endif
